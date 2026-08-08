#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Crash-safe reviewer Compose replacement, promotion, and reactivation.

One immutable plan and monotonic journal cover backup, reviewer replacement,
maintenance sealing, exact user-unit promotion, inhibited activation, durable
gate removal, and proof of a later scheduled reconciliation.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
import fcntl
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from types import SimpleNamespace
from typing import Any, Callable, Iterator, Mapping, NoReturn, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import reconcile_compose_deployment as reconciler  # noqa: E402
import reviewer_upgrade_backup as backup  # noqa: E402
import reviewer_upgrade_backup_docker as backup_docker  # noqa: E402
import reviewer_upgrade_finalize as finalize  # noqa: E402
import reviewer_upgrade_journal as journal  # noqa: E402
import reviewer_upgrade_manager as manager  # noqa: E402
import reviewer_upgrade_systemd as upgrade_systemd  # noqa: E402
import reviewer_upgrade_unit_artifacts as unit_artifacts  # noqa: E402


ACTIVE_CONTRACT = "tacua.reviewer-upgrade-active@1.0.0"
INHIBITOR_CONTRACT = "tacua.reviewer-upgrade-inhibitor@1.0.0"
ACTIVE_FILE = "active.json"
ACTIVE_STAGING_FILE = ".active.json.next"
CANDIDATE_COMPOSE_FILE = "candidate-compose.json"
INHIBITOR_FILE = "reviewer-upgrade-inhibitor.json"
INHIBITOR_STAGING_FILE = ".reviewer-upgrade-inhibitor.json.next"
SEALED_STATE_DIRECTORY = "sealed-state"
UPGRADES_DIRECTORY = "upgrades"
SERIAL_LOCK_FILE = "reviewer-upgrade.lock"
PROCESSING_LOCK_EPOCH_CONTRACT = (
    "tacua.reviewer-upgrade-processing-lock-epoch@1.0.0"
)
PROCESSING_LOCK_EPOCH_PREFIX = "processing-lock-epoch-"
PROCESSING_LOCK_EPOCH_NAME = re.compile(
    r"^processing-lock-epoch-([0-9]{8})\.json$"
)
MAX_SEAL_ATTEMPTS = 3
HEALTH_ATTEMPTS = 30
HEALTH_INTERVAL_SECONDS = 1.0
SCHEDULED_RECONCILE_DEADLINE_SECONDS = 180.0

OPERATION_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
REVIEWER_TAG = re.compile(
    r"^tacua-reviewer-web:[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
)
INGRESS_CONFIG_SUFFIX = Path("services/backend/ingress/haproxy.cfg")
COMPOSE_HASH = re.compile(r"^[a-f0-9]{64}$")

PREPARED = "prepared"
QUIESCING = "quiescing"
MAINTENANCE = "maintenance"
BACKING_UP = "backing_up"
BACKUP_READY = "backup_ready"
REPLACING = "replacing"
REVIEWER_READY = "reviewer_ready"
SEALING = "sealing"
SEALED_MAINTENANCE = "sealed_maintenance"
PROMOTING = "promoting"
SCHEDULED_MAINTENANCE = "scheduled_maintenance"
ACTIVATING = "activating"
COMPLETE = "complete"
SUPPORTED_PHASES = {
    PREPARED,
    QUIESCING,
    MAINTENANCE,
    BACKING_UP,
    BACKUP_READY,
    REPLACING,
    REVIEWER_READY,
    SEALING,
    SEALED_MAINTENANCE,
    PROMOTING,
    SCHEDULED_MAINTENANCE,
    ACTIVATING,
    COMPLETE,
}
PRE_REPLACEMENT_PHASES = {
    PREPARED,
    QUIESCING,
    MAINTENANCE,
    BACKING_UP,
}

OLD = "OLD"
ABSENT = "ABSENT"
CANDIDATE = "CANDIDATE"

GATE_PENDING = "pending"
GATE_DIRECTORY_BOUND = "directory_bound"
GATE_INHIBITOR_READY = "inhibitor_ready"

BACKUP_PLAN_KEYS = {
    "backend",
    "config",
    "contract_version",
    "operation_id",
    "project",
    "secret",
    "source",
}

FINALIZE_PLAN_KEYS = {
    "lock_file_binding",
    "manager_binaries",
    "processing_lock_epoch",
    "reconcile_bindings",
    "timer_enable_link_paths",
    "unit_directory",
}

LOCK_FILE_BINDING_KEYS = {"device", "inode", "mode", "path", "uid"}

INITIAL_PROCESSING_LOCK_EPOCH_KEYS = {
    "boot_id",
    "contract_version",
    "epoch_digest",
    "lock_file_binding",
    "sequence",
}

PROCESSING_LOCK_EPOCH_KEYS = {
    *INITIAL_PROCESSING_LOCK_EPOCH_KEYS,
    "plan_digest",
    "previous_epoch_digest",
}

RECONCILE_BINDING_KEYS = {
    "admin_secret_file",
    "anchor_file",
    "config_file",
    "lock_file",
    "operation_directory",
    "python",
    "reconciler",
    "state_directory",
}

ACTIVATION_PENDING = "pending"
ACTIVATION_RUNNING_GATE_HELD = "running_gate_held"
ACTIVATION_GATE_ABSENT = "gate_absent"

FATAL_FAILURE_CODES = frozenset(
    {
        "RECONCILE_ACTIVATION_PENDING",
        "RECONCILE_ANCHOR_INVALID",
        "RECONCILE_CONTAINER_DRIFT",
        "RECONCILE_INPUT_INVALID",
        "RECONCILE_LOCK_INVALID",
        "RECONCILE_PUBLIC_PATH_ACTIVE",
        "RECONCILE_PUBLIC_PATH_CRITICAL",
        "RECONCILE_RECOVERY_REQUIRED",
        "RECONCILE_RESOURCE_DRIFT",
        "RECONCILE_RUNNING_REQUIRED",
        "RECONCILE_RUNTIME_DRIFT",
        "RECONCILE_STATE_BINDING_MISMATCH",
        "RECONCILE_STATE_CHANGED",
        "RECONCILE_STATE_EXISTS",
        "RECONCILE_STATE_INVALID",
        "RECONCILE_UPGRADE_INHIBITOR_INVALID",
        "REVIEWER_UPGRADE_ACTIVE_EXISTS",
        "REVIEWER_UPGRADE_BACKUP_ATTEMPTS_EXHAUSTED",
        "REVIEWER_UPGRADE_BACKUP_CHANGED",
        "REVIEWER_UPGRADE_BACKUP_INVALID",
        "REVIEWER_UPGRADE_BACKUP_REQUIRED",
        "REVIEWER_UPGRADE_CANDIDATE_INVALID",
        "REVIEWER_UPGRADE_CANDIDATE_REBOUND",
        "REVIEWER_UPGRADE_CONTAINER_DRIFT",
        "REVIEWER_UPGRADE_DAEMON_DRIFT",
        "REVIEWER_UPGRADE_DEPLOYMENT_CHANGED",
        "REVIEWER_UPGRADE_INHIBITOR_AMBIGUOUS",
        "REVIEWER_UPGRADE_INHIBITOR_INVALID",
        "REVIEWER_UPGRADE_INPUT_INVALID",
        "REVIEWER_UPGRADE_JOURNAL_EXISTS",
        "REVIEWER_UPGRADE_JOURNAL_INVALID",
        "REVIEWER_UPGRADE_MAINTENANCE_INVALID",
        "REVIEWER_UPGRADE_NOT_FOUND",
        "REVIEWER_UPGRADE_RESOURCE_DRIFT",
        "REVIEWER_UPGRADE_RUNNING_REQUIRED",
        "REVIEWER_UPGRADE_SEALED_STATE_EXISTS",
        "REVIEWER_UPGRADE_SEALED_STATE_INVALID",
        "REVIEWER_UPGRADE_SEAL_ATTEMPTS_EXHAUSTED",
        "REVIEWER_UPGRADE_SERIAL_LOCK_INVALID",
        "REVIEWER_UPGRADE_SOURCE_CHANGED",
        "REVIEWER_UPGRADE_STATE_CHANGED",
        "REVIEWER_UPGRADE_STATE_INVALID",
        "UPGRADE_FINALIZE_GATE_INVALID",
        "UPGRADE_FINALIZE_INPUT_INVALID",
        "UPGRADE_FINALIZE_LOCK_INVALID",
        "UPGRADE_FINALIZE_RECEIPT_INVALID",
        "UPGRADE_FINALIZE_STATE_INVALID",
        "UPGRADE_FINALIZE_TIMER_LINK_INVALID",
        "UPGRADE_FINALIZE_UNIT_INVALID",
        "UPGRADE_FINALIZE_UNIT_UNKNOWN",
        "UPGRADE_MANAGER_CLOCK_INVALID",
        "UPGRADE_MANAGER_EXPECTATION_INVALID",
        "UPGRADE_MANAGER_INPUT_INVALID",
        "UPGRADE_MANAGER_INVOCATION_INVALID",
        "UPGRADE_MANAGER_LOADED_UNIT_INVALID",
        "UPGRADE_MANAGER_LOCK_HANDOFF_INVALID",
        "UPGRADE_UNIT_ARTIFACT_INVALID",
    }
)

RETRYABLE_FAILURE_CODES = frozenset(
    {
        "RECONCILE_COMMAND_FAILED",
        "RECONCILE_DEFERRED",
        "RECONCILE_DOCKER_START_FAILED",
        "RECONCILE_FAILED",
        "RECONCILE_HEALTH_FAILED",
        "RECONCILE_SMOKE_FAILED",
        "RECONCILE_TAILNET_FAILED",
        "REVIEWER_UPGRADE_BACKUP_FAILED",
        "REVIEWER_UPGRADE_BACKUP_RECOVERY_FAILED",
        "REVIEWER_UPGRADE_FAILED",
        "REVIEWER_UPGRADE_HEALTH_FAILED",
        "REVIEWER_UPGRADE_LOCK_CONTENDED",
        "REVIEWER_UPGRADE_PUBLIC_PATH_INVALID",
        "REVIEWER_UPGRADE_SEAL_INCOMPLETE",
        "REVIEWER_UPGRADE_WAITING_MAINTENANCE",
        "UPGRADE_FINALIZE_ACTIVATION_FAILED",
        "UPGRADE_FINALIZE_LOCK_CONTENDED",
        "UPGRADE_FINALIZE_MANAGER_FAILED",
        "UPGRADE_FINALIZE_SCHEDULED_FAILED",
        "UPGRADE_MANAGER_DAEMON_RELOAD_FAILED",
        "UPGRADE_MANAGER_LOCK_CONTENDED",
        "UPGRADE_MANAGER_LOCK_HANDOFF_FAILED",
        "UPGRADE_MANAGER_LOCK_RESTART_FAILED",
        "UPGRADE_MANAGER_MAINTENANCE_NOT_PROVEN",
        "UPGRADE_MANAGER_RECONCILE_FAILED",
        "UPGRADE_MANAGER_SCHEDULED_RECONCILE_FAILED",
        "UPGRADE_MANAGER_SCHEDULED_RECONCILE_TIMEOUT",
        "UPGRADE_MANAGER_TIMER_ARM_FAILED",
        "UPGRADE_MANAGER_TIMER_NOT_WAITING",
        "UPGRADE_MANAGER_TIMER_QUIESCE_FAILED",
        "UPGRADE_MANAGER_UNIT_VERIFY_FAILED",
    }
)

Runner = Callable[..., bytes]
BackupRunner = Callable[[str, Mapping[str, Any]], Mapping[str, Any]]


class UpgradeError(RuntimeError):
    """A stable, content-free reviewer-upgrade error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        raise UpgradeError("REVIEWER_UPGRADE_INPUT_INVALID")


def _fail(code: str = "REVIEWER_UPGRADE_STATE_INVALID") -> NoReturn:
    raise UpgradeError(code)


def _canonical_path(value: Path, code: str) -> Path:
    if (
        not value.is_absolute()
        or str(value).startswith("//")
        or any(part in {".", ".."} for part in value.parts)
    ):
        raise UpgradeError(code)
    try:
        if value.resolve(strict=True) != value:
            raise UpgradeError(code)
    except OSError as error:
        raise UpgradeError(code) from error
    return value


def _ensure_upgrades_directory(state_parent: Path) -> Path:
    parent = reconciler._safe_directory(
        _canonical_path(state_parent, "REVIEWER_UPGRADE_INPUT_INVALID")
    )
    upgrades = parent / UPGRADES_DIRECTORY
    created = False
    try:
        upgrades.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
    upgrades = reconciler._safe_directory(upgrades)
    if created:
        reconciler._fsync_directory(parent)
    return upgrades


def _existing_upgrades_directory(state_parent: Path) -> Path | None:
    parent = reconciler._safe_directory(
        _canonical_path(state_parent, "REVIEWER_UPGRADE_INPUT_INVALID")
    )
    upgrades = parent / UPGRADES_DIRECTORY
    if not upgrades.exists() and not upgrades.is_symlink():
        return None
    return reconciler._safe_directory(upgrades)


def _active_digest(document: Mapping[str, Any]) -> str:
    return reconciler._document_digest(document, "active_digest")


def _validate_active(value: Any) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {"active_digest", "contract_version", "operation_id", "plan_digest"}
        or value.get("contract_version") != ACTIVE_CONTRACT
        or OPERATION_ID.fullmatch(str(value.get("operation_id"))) is None
        or reconciler.DIGEST.fullmatch(str(value.get("plan_digest"))) is None
        or value.get("active_digest") != _active_digest(value)
        or journal.canonical_json(value) != reconciler._canonical(value)
    ):
        _fail()
    return dict(value)


@contextmanager
def _active_directory_lock(upgrades: Path) -> Iterator[None]:
    upgrades = reconciler._safe_directory(upgrades)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(upgrades, flags)
        before = os.fstat(descriptor)
        lexical = upgrades.lstat()
        if (
            (before.st_dev, before.st_ino) != (lexical.st_dev, lexical.st_ino)
            or not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o700
        ):
            _fail()
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        current = upgrades.lstat()
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            _fail()
        yield
        after = os.fstat(descriptor)
        current = upgrades.lstat()
        if (
            (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
            or after.st_uid != os.geteuid()
            or current.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) != 0o700
            or stat.S_IMODE(current.st_mode) != 0o700
        ):
            _fail()
    except UpgradeError:
        raise
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
    finally:
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(descriptor)
            except OSError:
                pass


def _fsync_validated_directory(path: Path) -> None:
    directory = reconciler._safe_directory(path)
    descriptor: int | None = None
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(directory, flags)
        before = os.fstat(descriptor)
        lexical = directory.lstat()
        expected = (
            before.st_dev,
            before.st_ino,
            stat.S_IMODE(before.st_mode),
            before.st_uid,
            before.st_gid,
        )
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid()
            or expected
            != (
                lexical.st_dev,
                lexical.st_ino,
                stat.S_IMODE(lexical.st_mode),
                lexical.st_uid,
                lexical.st_gid,
            )
        ):
            _fail("REVIEWER_UPGRADE_STATE_INVALID")
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        current = directory.lstat()
        if expected != (
            after.st_dev,
            after.st_ino,
            stat.S_IMODE(after.st_mode),
            after.st_uid,
            after.st_gid,
        ) or expected != (
            current.st_dev,
            current.st_ino,
            stat.S_IMODE(current.st_mode),
            current.st_uid,
            current.st_gid,
        ):
            _fail("REVIEWER_UPGRADE_STATE_INVALID")
    except UpgradeError:
        raise
    except (OSError, reconciler.ReconcileError) as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _load_active_locked(
    upgrades: Path,
    *,
    optional: bool,
) -> dict[str, str] | None:
    _repair_active_publication_locked(upgrades)
    path = upgrades / ACTIVE_FILE
    if not path.exists() and not path.is_symlink():
        if optional:
            return None
        _fail("REVIEWER_UPGRADE_NOT_FOUND")
    payload = reconciler._read_private(
        path,
        mode=0o600,
        code="REVIEWER_UPGRADE_STATE_INVALID",
    )
    try:
        value = journal.parse_canonical_json(payload)
    except journal.JournalError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
    active = _validate_active(value)
    if payload != journal.canonical_json(active):
        _fail()
    return active


def _load_active(upgrades: Path, *, optional: bool = False) -> dict[str, str] | None:
    with _active_directory_lock(upgrades):
        return _load_active_locked(upgrades, optional=optional)


def _private_regular_metadata(path: Path, *, links: set[int]) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink not in links
    ):
        _fail()
    return metadata


def _repair_active_publication_locked(upgrades: Path) -> None:
    """Repair only the exact hard-link publication crash state."""

    active = upgrades / ACTIVE_FILE
    staging = upgrades / ACTIVE_STAGING_FILE
    active_exists = active.exists() or active.is_symlink()
    staging_exists = staging.exists() or staging.is_symlink()
    if not staging_exists:
        return
    if not active_exists:
        # Exact staging without the link is pre-commit.  Never publish it;
        # discard it under the upgrades-directory lock and fsync the removal.
        _private_regular_metadata(staging, links={1})
        try:
            staging.unlink()
            reconciler._fsync_directory(upgrades)
        except OSError as error:
            raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
        return
    active_metadata = _private_regular_metadata(active, links={2})
    staging_metadata = _private_regular_metadata(staging, links={2})
    if (active_metadata.st_dev, active_metadata.st_ino) != (
        staging_metadata.st_dev,
        staging_metadata.st_ino,
    ):
        _fail()
    try:
        staging.unlink()
        reconciler._fsync_directory(upgrades)
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error


def _write_private_staging(path: Path, payload: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("active selector write stopped")
                offset += written
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error


def _publish_active(upgrades: Path, operation_id: str, plan_digest: str) -> dict[str, str]:
    with _active_directory_lock(upgrades):
        if _load_active_locked(upgrades, optional=True) is not None:
            _fail("REVIEWER_UPGRADE_ACTIVE_EXISTS")
        document: dict[str, str] = {
            "active_digest": "",
            "contract_version": ACTIVE_CONTRACT,
            "operation_id": operation_id,
            "plan_digest": plan_digest,
        }
        document["active_digest"] = _active_digest(document)
        document = _validate_active(document)
        payload = journal.canonical_json(document)
        active_path = upgrades / ACTIVE_FILE
        staging_path = upgrades / ACTIVE_STAGING_FILE
        if staging_path.exists() or staging_path.is_symlink():
            _fail()
        _write_private_staging(staging_path, payload)
        try:
            # link(2) is the portable no-clobber publication primitive.  The
            # deterministic staging sibling makes its sole crash state repairable.
            os.link(staging_path, active_path, follow_symlinks=False)
            reconciler._fsync_directory(upgrades)
            staging_path.unlink()
            reconciler._fsync_directory(upgrades)
        except FileExistsError as error:
            try:
                staging_path.unlink()
                reconciler._fsync_directory(upgrades)
            except OSError:
                pass
            raise UpgradeError("REVIEWER_UPGRADE_ACTIVE_EXISTS") from error
        except OSError as error:
            raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
        loaded = _load_active_locked(upgrades, optional=False)
        if loaded != document:
            _fail()
        return document


def _backup_plan_payload(
    operation_id: str,
    source: Path,
    manifest: Mapping[str, Any],
    compose_document: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        backend = manifest["containers"]["backend"]
        image_ref = compose_document["services"]["backend"]["image"]
        state_volume = compose_document["volumes"]["tacua-state"]["name"]
        mounted = [
            mount
            for mount in backend["mounts"]
            if mount.get("Destination") == "/var/lib/tacua"
        ]
    except (KeyError, TypeError) as error:
        raise UpgradeError("REVIEWER_UPGRADE_BACKUP_INVALID") from error
    if (
        not isinstance(backend, dict)
        or not isinstance(image_ref, str)
        or backend.get("config", {}).get("Image") != image_ref
        or not isinstance(state_volume, str)
        or len(mounted) != 1
        or mounted[0].get("Type") != "volume"
        or mounted[0].get("Name") != state_volume
        or mounted[0].get("RW") is not True
        or mounted[0].get("Destination") != "/var/lib/tacua"
    ):
        _fail("REVIEWER_UPGRADE_BACKUP_INVALID")
    payload = {
        "backend": {
            "container_id": backend.get("id"),
            "image_id": backend.get("image_id"),
            "image_ref": image_ref,
            "state_volume": state_volume,
        },
        "config": {
            key: manifest["config"][key]
            for key in ("digest", "mode", "path", "size", "uid")
        },
        "contract_version": backup.BACKUP_BINDINGS_CONTRACT,
        "operation_id": operation_id,
        "project": manifest["project"],
        "secret": {
            key: manifest["secret"][key]
            for key in ("digest", "mode", "path", "size", "uid")
        },
        "source": {
            "compose_digest": manifest["compose_digest"],
            "generation": manifest["generation"],
            "manifest_digest": manifest["manifest_digest"],
            "state_directory": str(source),
        },
    }
    try:
        backup.validate_backup_bindings(
            {**payload, "plan_digest": "sha256:" + "0" * 64}
        )
    except backup.BackupError as error:
        raise UpgradeError(error.code) from error
    return payload


def _backup_bindings(
    plan_document: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> backup.BackupBindings:
    raw = plan.get("backup")
    if not isinstance(raw, dict) or set(raw) != BACKUP_PLAN_KEYS:
        _fail("REVIEWER_UPGRADE_BACKUP_INVALID")
    try:
        bindings = backup.validate_backup_bindings(
            {**raw, "plan_digest": plan_document["plan_digest"]}
        )
    except (KeyError, TypeError, backup.BackupError) as error:
        raise UpgradeError("REVIEWER_UPGRADE_BACKUP_INVALID") from error
    if (
        bindings.operation_id != plan.get("operation_id")
        or bindings.project != plan.get("project")
        or str(bindings.source_state_directory)
        != plan.get("source_state_directory")
        or bindings.source_generation != plan.get("source_generation")
        or bindings.source_manifest_digest
        != plan.get("source_manifest_digest")
        or bindings.source_compose_digest != plan.get("source_compose_digest")
    ):
        _fail("REVIEWER_UPGRADE_BACKUP_INVALID")
    return bindings


def _live_backup_bindings(
    plan_document: Mapping[str, Any],
    plan: Mapping[str, Any],
    manifest: Mapping[str, Any],
    compose: Path,
) -> backup.BackupBindings:
    bindings = _backup_bindings(plan_document, plan)
    compose_document = reconciler._parse_json(
        reconciler._read_private(
            compose,
            mode=0o400,
            code="REVIEWER_UPGRADE_BACKUP_INVALID",
        ),
        "REVIEWER_UPGRADE_BACKUP_INVALID",
    )
    if not isinstance(compose_document, dict):
        _fail("REVIEWER_UPGRADE_BACKUP_INVALID")
    expected = _backup_plan_payload(
        plan["operation_id"],
        Path(plan["source_state_directory"]),
        manifest,
        compose_document,
    )
    if expected != plan["backup"]:
        _fail("REVIEWER_UPGRADE_BACKUP_INVALID")
    return bindings


def _plan_path(value: Any) -> Path:
    if type(value) is not str:
        _fail("REVIEWER_UPGRADE_INPUT_INVALID")
    path = Path(value)
    if (
        not path.is_absolute()
        or str(path) != value
        or value.startswith("//")
        or any(part in {".", ".."} for part in path.parts)
        or any(
            character in upgrade_systemd.UNSAFE_SYSTEMD_PATH_CHARACTERS
            for character in value
        )
    ):
        _fail("REVIEWER_UPGRADE_INPUT_INVALID")
    return path


def _bound_lock_file(lock_file: Path, descriptor: int) -> dict[str, Any]:
    try:
        record = reconciler._validate_lock_descriptor(descriptor, lock_file)
    except reconciler.ReconcileError as error:
        raise UpgradeError("REVIEWER_UPGRADE_INPUT_INVALID") from error
    if set(record) != LOCK_FILE_BINDING_KEYS or record["path"] != str(lock_file):
        _fail("REVIEWER_UPGRADE_INPUT_INVALID")
    return dict(record)


def _current_boot_id(code: str) -> str:
    try:
        value = reconciler._boot_id()
    except reconciler.ReconcileError as error:
        raise UpgradeError(code) from error
    if reconciler.BOOT_ID.fullmatch(value) is None:
        _fail(code)
    return value


def _epoch_digest(value: Mapping[str, Any]) -> str:
    try:
        return reconciler._document_digest(value, "epoch_digest")
    except (TypeError, ValueError, reconciler.ReconcileError) as error:
        raise UpgradeError("UPGRADE_FINALIZE_LOCK_INVALID") from error


def _initial_processing_lock_epoch(
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "boot_id": _current_boot_id("REVIEWER_UPGRADE_INPUT_INVALID"),
        "contract_version": PROCESSING_LOCK_EPOCH_CONTRACT,
        "epoch_digest": "",
        "lock_file_binding": dict(binding),
        "sequence": 0,
    }
    value["epoch_digest"] = _epoch_digest(value)
    return value


def _prepare_finalize_plan(
    transaction: Path,
    sealed_state: Path,
    manifest: Mapping[str, Any],
    *,
    candidate_repository_root: Path,
    unit_directory: Path,
    lock_file: Path,
    operation_directory: Path,
    lock_descriptor: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Snapshot and persist both exact unit bundles before plan publication."""

    units = _canonical_path(
        unit_directory,
        "REVIEWER_UPGRADE_INPUT_INVALID",
    )
    operations = _canonical_path(
        operation_directory,
        "REVIEWER_UPGRADE_INPUT_INVALID",
    )
    if not isinstance(candidate_repository_root, Path):
        _fail("REVIEWER_UPGRADE_INPUT_INVALID")
    candidate_repository = _canonical_path(
        candidate_repository_root,
        "REVIEWER_UPGRADE_INPUT_INVALID",
    )
    candidate_backend = candidate_repository / "services" / "backend"
    expected_lock = reconciler._lock_path(str(manifest.get("project")))
    if (
        not isinstance(lock_file, Path)
        or lock_file != expected_lock
        or not lock_file.is_absolute()
        or str(lock_file).startswith("//")
        or any(part in {".", ".."} for part in lock_file.parts)
        or operations != Path(str(manifest.get("operation_directory")))
    ):
        _fail("REVIEWER_UPGRADE_INPUT_INVALID")
    try:
        runtime = manifest["runtime"]
        commands = manifest["commands"]
        python = Path(sys.executable).resolve(strict=True)
        reconciler_path = _canonical_path(
            candidate_backend / "scripts" / "reconcile_compose_deployment.py",
            "REVIEWER_UPGRADE_INPUT_INVALID",
        )
        systemd_templates = _canonical_path(
            candidate_backend / "systemd",
            "REVIEWER_UPGRADE_INPUT_INVALID",
        )
        anchor = Path(runtime["xdg_runtime_directory"]) / "tacua-reconcile.anchor.json"
        systemctl = Path(commands["systemctl"])
        systemd_analyze = systemctl.with_name("systemd-analyze")
        target_bindings = upgrade_systemd.ReconcileUnitBindings(
            python=python,
            reconciler=reconciler_path,
            state_directory=sealed_state,
            lock_file=lock_file,
            anchor_file=anchor,
            operation_directory=operations,
            config_file=Path(manifest["config"]["path"]),
            admin_secret_file=Path(manifest["secret"]["path"]),
        )
        # Validate every substitution even before the pure renderer consumes it.
        replacements = target_bindings.replacements()
        old_units = upgrade_systemd.snapshot_installed_units(units)
        target_units = upgrade_systemd.render_reconcile_unit_bundle(
            systemd_templates,
            target_bindings,
        )
        descriptors = unit_artifacts.prepare_unit_bundle_artifacts(
            transaction,
            old_units,
            target_units,
        )
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise UpgradeError("REVIEWER_UPGRADE_INPUT_INVALID") from error
    except (upgrade_systemd.UnitContractError, unit_artifacts.UnitArtifactError) as error:
        raise UpgradeError("UPGRADE_UNIT_ARTIFACT_INVALID") from error
    lock_binding = _bound_lock_file(lock_file, lock_descriptor)
    finalize_plan = {
        "lock_file_binding": lock_binding,
        "manager_binaries": {
            "systemctl": str(systemctl),
            "systemd_analyze": str(systemd_analyze),
        },
        "reconcile_bindings": {
            "admin_secret_file": replacements["@ADMIN_SECRET_FILE@"],
            "anchor_file": replacements["@ANCHOR_FILE@"],
            "config_file": replacements["@CONFIG_FILE@"],
            "lock_file": replacements["@LOCK_FILE@"],
            "operation_directory": replacements["@OPERATION_DIRECTORY@"],
            "python": replacements["@PYTHON@"],
            "reconciler": replacements["@RECONCILER@"],
            "state_directory": replacements["@STATE_DIRECTORY@"],
        },
        "processing_lock_epoch": _initial_processing_lock_epoch(lock_binding),
        "timer_enable_link_paths": [
            str(units / "timers.target.wants" / manager.RECONCILE_TIMER)
        ],
        "unit_directory": str(units),
    }
    _validate_finalize_plan(
        finalize_plan,
        str(sealed_state),
        str(candidate_repository),
        manifest,
    )
    return finalize_plan, descriptors


def _validate_finalize_plan(
    value: Any,
    sealed_state_directory: str,
    candidate_repository_root: str,
    manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != FINALIZE_PLAN_KEYS:
        _fail()
    manager_binaries = value.get("manager_binaries")
    lock_binding = value.get("lock_file_binding")
    lock_epoch = value.get("processing_lock_epoch")
    reconcile_bindings = value.get("reconcile_bindings")
    links = value.get("timer_enable_link_paths")
    if (
        not isinstance(manager_binaries, dict)
        or set(manager_binaries) != {"systemctl", "systemd_analyze"}
        or not isinstance(reconcile_bindings, dict)
        or set(reconcile_bindings) != RECONCILE_BINDING_KEYS
        or not isinstance(links, list)
        or len(links) != 1
        or any(type(item) is not str for item in links)
    ):
        _fail()
    paths = {
        key: _plan_path(path)
        for key, path in {
            "unit_directory": value.get("unit_directory"),
            **manager_binaries,
            **reconcile_bindings,
            "timer_enable_link": links[0],
        }.items()
    }
    candidate_repository = _plan_path(candidate_repository_root)
    expected_reconciler = (
        candidate_repository
        / "services"
        / "backend"
        / "scripts"
        / "reconcile_compose_deployment.py"
    )
    if (
        paths["state_directory"] != Path(sealed_state_directory)
        or paths["reconciler"] != expected_reconciler
        or paths["systemctl"].name != "systemctl"
        or paths["systemd_analyze"].name != "systemd-analyze"
        or paths["python"] == paths["reconciler"]
        or paths["timer_enable_link"]
        != paths["unit_directory"] / "timers.target.wants" / manager.RECONCILE_TIMER
    ):
        _fail()
    if (
        not isinstance(lock_binding, dict)
        or set(lock_binding) != LOCK_FILE_BINDING_KEYS
        or any(
            type(lock_binding.get(key)) is not int
            for key in ("device", "inode", "mode", "uid")
        )
        or lock_binding.get("device", -1) < 0
        or lock_binding.get("inode", 0) <= 0
        or lock_binding.get("mode") != 0o600
        or lock_binding.get("uid") != os.geteuid()
        or lock_binding.get("path") != str(paths["lock_file"])
    ):
        _fail()
    if (
        not isinstance(lock_epoch, dict)
        or set(lock_epoch) != INITIAL_PROCESSING_LOCK_EPOCH_KEYS
        or lock_epoch.get("contract_version")
        != PROCESSING_LOCK_EPOCH_CONTRACT
        or lock_epoch.get("sequence") != 0
        or reconciler.BOOT_ID.fullmatch(str(lock_epoch.get("boot_id"))) is None
        or lock_epoch.get("lock_file_binding") != lock_binding
        or reconciler.DIGEST.fullmatch(str(lock_epoch.get("epoch_digest")))
        is None
        or lock_epoch.get("epoch_digest") != _epoch_digest(lock_epoch)
    ):
        _fail()
    if manifest is not None:
        if (
            paths["operation_directory"]
            != Path(str(manifest.get("operation_directory")))
            or paths["lock_file"]
            != reconciler._lock_path(str(manifest.get("project")))
            or paths["config_file"] != Path(str(manifest.get("config", {}).get("path")))
            or paths["admin_secret_file"]
            != Path(str(manifest.get("secret", {}).get("path")))
            or paths["anchor_file"]
            != Path(str(manifest.get("runtime", {}).get("xdg_runtime_directory")))
            / "tacua-reconcile.anchor.json"
            or paths["systemctl"]
            != Path(str(manifest.get("commands", {}).get("systemctl")))
        ):
            _fail()
    return deepcopy(value)


def _bind_resume_abi(
    plan: Mapping[str, Any],
    *,
    unit_directory: Path | None,
    lock_file: Path | None,
    operation_directory: Path | None,
) -> tuple[Path, Path, Path]:
    bindings = plan["finalize"]["reconcile_bindings"]
    expected = (
        _plan_path(plan["finalize"]["unit_directory"]),
        _plan_path(bindings["lock_file"]),
        _plan_path(bindings["operation_directory"]),
    )
    supplied = (unit_directory, lock_file, operation_directory)
    for actual, sealed in zip(supplied, expected, strict=True):
        if actual is None:
            # Direct in-process callers may use the immutable values.  The CLI
            # requires all three arguments, so production cannot omit them.
            continue
        if not isinstance(actual, Path) or _plan_path(str(actual)) != sealed:
            _fail("REVIEWER_UPGRADE_INPUT_INVALID")
    return expected


def _loaded_target_expectations(
    finalize_plan: Mapping[str, Any],
) -> dict[str, manager.LoadedUnitExpectation]:
    unit_directory = _plan_path(finalize_plan["unit_directory"])
    raw = finalize_plan["reconcile_bindings"]
    python = _plan_path(raw["python"])
    reconciler_path = _plan_path(raw["reconciler"])
    state = _plan_path(raw["state_directory"])
    anchor = _plan_path(raw["anchor_file"])
    return {
        manager.RECONCILE_SERVICE: manager.LoadedUnitExpectation(
            unit_directory / manager.RECONCILE_SERVICE,
            manager.ExecStartBinding(
                python,
                (
                    str(python),
                    "-B",
                    str(reconciler_path),
                    "reconcile",
                    "--state-directory",
                    str(state),
                    "--anchor-file",
                    str(anchor),
                ),
            ),
        ),
        manager.RECONCILE_LOCK_SERVICE: manager.LoadedUnitExpectation(
            unit_directory / manager.RECONCILE_LOCK_SERVICE,
            manager.ExecStartBinding(
                python,
                (
                    str(python),
                    "-B",
                    str(reconciler_path),
                    "prepare-lock",
                    "--state-directory",
                    str(state),
                    "--anchor-file",
                    str(anchor),
                ),
            ),
        ),
        manager.RECONCILE_TIMER: manager.LoadedUnitExpectation(
            unit_directory / manager.RECONCILE_TIMER,
            None,
        ),
    }


def _finalize_bindings(
    transaction: Path,
    plan: Mapping[str, Any],
    plan_digest: str,
    gate: Mapping[str, Any],
    lock_holder: dict[str, Any],
) -> finalize.FinalizeBindings:
    try:
        old_units, target_units = unit_artifacts.load_unit_bundle_artifacts(
            transaction,
            plan["unit_artifacts"],
        )
    except unit_artifacts.UnitArtifactError as error:
        raise UpgradeError("UPGRADE_UNIT_ARTIFACT_INVALID") from error
    target_state = _plan_path(plan["sealed_state_directory"])
    try:
        _desired, target_manifest, _compose = reconciler._load_bound_state(
            target_state
        )
    except reconciler.ReconcileError as error:
        raise UpgradeError("UPGRADE_FINALIZE_STATE_INVALID") from error
    finalize_plan = _validate_finalize_plan(
        plan["finalize"],
        plan["sealed_state_directory"],
        plan["candidate_repository_root"],
        target_manifest,
    )
    sealed_gate = _validate_processing_gate(
        gate,
        plan,
        plan_digest,
        manifest=target_manifest,
        require_live=False,
    )
    binding = sealed_gate["operation_directory_binding"]
    inhibitor = sealed_gate["inhibitor"]
    manager_binaries = finalize_plan["manager_binaries"]
    return finalize.FinalizeBindings(
        target_state_directory=target_state,
        unit_directory=_plan_path(finalize_plan["unit_directory"]),
        old_units=old_units,
        target_units=target_units,
        manager_binaries=manager.ManagerBinaries(
            _plan_path(manager_binaries["systemctl"]),
            _plan_path(manager_binaries["systemd_analyze"]),
        ),
        loaded_target=_loaded_target_expectations(finalize_plan),
        timer_enable_link_paths=tuple(
            _plan_path(path)
            for path in finalize_plan["timer_enable_link_paths"]
        ),
        processing_gate=finalize.ProcessingGateBinding(
            operation_directory=_plan_path(sealed_gate["operation_directory"]),
            directory_identity=finalize.DirectoryIdentity(
                device=binding["device"],
                gid=binding["gid"],
                inode=binding["inode"],
                mode=binding["mode"],
                uid=binding["uid"],
            ),
            inhibitor=finalize.UpgradeInhibitor(
                contract_version=inhibitor["contract_version"],
                inhibitor_digest=inhibitor["inhibitor_digest"],
                plan_digest=inhibitor["plan_digest"],
                project=inhibitor["project"],
            ),
        ),
        processing_lock=_processing_lock_callbacks(
            lock_holder,
            plan["project"],
            _plan_path(finalize_plan["reconcile_bindings"]["lock_file"]),
            lock_holder.get(
                "expected_binding",
                finalize_plan["lock_file_binding"],
            ),
        ),
    )


def _validate_finalize_receipt(
    value: Any,
    *,
    operation: str,
    status: str,
    project: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "contract_version",
            "details",
            "generation",
            "operation",
            "project",
            "receipt_digest",
            "status",
        }
        or value.get("contract_version") != finalize.RECEIPT_CONTRACT
        or not isinstance(value.get("details"), dict)
        or reconciler.GENERATION.fullmatch(str(value.get("generation"))) is None
        or value.get("operation") != operation
        or value.get("project") != project
        or value.get("status") != status
        or value.get("receipt_digest")
        != reconciler._document_digest(value, "receipt_digest")
    ):
        _fail("UPGRADE_FINALIZE_RECEIPT_INVALID")
    try:
        if reconciler._parse_json(
            reconciler._canonical(value),
            "UPGRADE_FINALIZE_RECEIPT_INVALID",
        ) != value:
            _fail("UPGRADE_FINALIZE_RECEIPT_INVALID")
    except reconciler.ReconcileError as error:
        raise UpgradeError("UPGRADE_FINALIZE_RECEIPT_INVALID") from error
    return deepcopy(value)


def _validate_plan(plan_document: Mapping[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(plan_document, dict)
        or set(plan_document) != {"contract_version", "plan", "plan_digest"}
        or not isinstance(plan_document.get("plan"), dict)
    ):
        _fail()
    plan = plan_document["plan"]
    required = {
        "backup",
        "candidate_compose_digest",
        "candidate_image_id",
        "candidate_image_ref",
        "candidate_repository_root",
        "finalize",
        "operation_id",
        "prepared_desired",
        "project",
        "source_compose_digest",
        "source_generation",
        "source_manifest_digest",
        "source_repository_root",
        "source_state_directory",
        "sealed_state_directory",
        "serial_lock",
        "unit_artifacts",
    }
    desired = plan.get("prepared_desired")
    if (
        set(plan) != required
        or OPERATION_ID.fullmatch(str(plan.get("operation_id"))) is None
        or reconciler.PROJECT.fullmatch(str(plan.get("project"))) is None
        or reconciler.GENERATION.fullmatch(str(plan.get("source_generation")))
        is None
        or any(
            reconciler.DIGEST.fullmatch(str(plan.get(key))) is None
            for key in (
                "candidate_compose_digest",
                "candidate_image_id",
                "source_compose_digest",
                "source_manifest_digest",
            )
        )
        or REVIEWER_TAG.fullmatch(str(plan.get("candidate_image_ref"))) is None
        or str(plan.get("candidate_image_ref")).rsplit(":", 1)[-1].lower()
        == "latest"
        or not isinstance(desired, dict)
        or set(desired)
        != {
            "compose_digest",
            "contract_version",
            "desired",
            "generation",
            "manifest_digest",
            "project",
            "state_digest",
        }
        or desired.get("contract_version") != reconciler.DESIRED_CONTRACT
        or desired.get("desired") != "running"
        or desired.get("generation") != plan.get("source_generation")
        or desired.get("manifest_digest") != plan.get("source_manifest_digest")
        or desired.get("compose_digest") != plan.get("source_compose_digest")
        or desired.get("project") != plan.get("project")
        or desired.get("state_digest")
        != reconciler._document_digest(desired, "state_digest")
    ):
        _fail()
    state_path = Path(str(plan.get("source_state_directory")))
    sealed_path = Path(str(plan.get("sealed_state_directory")))
    source_repository = _plan_path(plan.get("source_repository_root"))
    candidate_repository = _plan_path(plan.get("candidate_repository_root"))
    if (
        str(state_path) != plan.get("source_state_directory")
        or not state_path.is_absolute()
        or str(state_path).startswith("//")
        or any(part in {".", ".."} for part in state_path.parts)
        or str(sealed_path) != plan.get("sealed_state_directory")
        or not sealed_path.is_absolute()
        or sealed_path.name != SEALED_STATE_DIRECTORY
        or source_repository == candidate_repository
    ):
        _fail()
    _backup_bindings(plan_document, plan)
    _validated_lock_binding(
        plan["serial_lock"],
        state_path.parent / SERIAL_LOCK_FILE,
        "REVIEWER_UPGRADE_SERIAL_LOCK_INVALID",
    )
    _validate_finalize_plan(
        plan["finalize"],
        plan["sealed_state_directory"],
        plan["candidate_repository_root"],
    )
    try:
        unit_artifacts.validate_unit_artifact_descriptors(plan["unit_artifacts"])
    except unit_artifacts.UnitArtifactError as error:
        raise UpgradeError("UPGRADE_UNIT_ARTIFACT_INVALID") from error
    return dict(plan)


def _transaction_directory(upgrades: Path, operation_id: str) -> Path:
    if OPERATION_ID.fullmatch(operation_id) is None:
        _fail()
    transaction = upgrades / operation_id
    if transaction.parent != upgrades:
        _fail()
    try:
        return journal.validate_transaction_directory(transaction)
    except journal.JournalError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error


def _load_transaction(
    upgrades: Path,
    active: Mapping[str, str],
) -> tuple[Path, dict[str, Any], dict[str, Any], dict[str, Any]]:
    transaction = _transaction_directory(upgrades, active["operation_id"])
    try:
        plan_document = journal.load_plan(transaction)
        progress = journal.load_progress(transaction, plan_document)
    except journal.JournalError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
    plan = _validate_plan(plan_document)
    if (
        plan_document["plan_digest"] != active["plan_digest"]
        or plan["operation_id"] != active["operation_id"]
        or Path(plan["source_state_directory"]).parent != upgrades.parent
        or Path(plan["sealed_state_directory"])
        != transaction / SEALED_STATE_DIRECTORY
        or progress is None
        or progress.get("phase") not in SUPPORTED_PHASES
    ):
        _fail()
    _validate_progress(
        progress,
        transaction,
        plan,
        plan_document["plan_digest"],
    )
    return transaction, plan_document, plan, progress


def _candidate_compose(
    transaction: Path,
    plan: Mapping[str, Any],
) -> tuple[Path, bytes, dict[str, Any]]:
    path = transaction / CANDIDATE_COMPOSE_FILE
    payload = reconciler._read_private(
        path,
        mode=0o600,
        code="REVIEWER_UPGRADE_STATE_INVALID",
    )
    if reconciler._digest(payload) != plan["candidate_compose_digest"]:
        _fail()
    document = reconciler._parse_json(payload, "REVIEWER_UPGRADE_STATE_INVALID")
    if not isinstance(document, dict):
        _fail()
    return path, payload, document


def _expected_maintenance(desired: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(desired)
    value["desired"] = "maintenance"
    value["state_digest"] = reconciler._document_digest(value, "state_digest")
    return value


def _load_source_transition_state(
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], Path, dict[str, Any] | None]:
    source = Path(plan["source_state_directory"])
    desired, manifest, compose = reconciler._load_bound_state(source)
    prepared = plan["prepared_desired"]
    allowed = [prepared, _expected_maintenance(prepared)]
    activation = reconciler._load_activation(source, desired)
    if (
        prepared["desired"] != "running"
        or desired not in allowed
        or manifest["manifest_digest"] != plan["source_manifest_digest"]
        or manifest["compose_digest"] != plan["source_compose_digest"]
        or manifest["generation"] != plan["source_generation"]
        or manifest["project"] != plan["project"]
        or compose.parent.parent.name != "generations"
    ):
        _fail("REVIEWER_UPGRADE_SOURCE_CHANGED")
    if activation is not None and activation.get("intent") != "maintenance":
        _fail("REVIEWER_UPGRADE_SOURCE_CHANGED")
    return desired, manifest, compose, activation


def _validate_source_state(
    plan: Mapping[str, Any],
    *,
    require_maintenance: bool,
) -> tuple[dict[str, Any], dict[str, Any], Path]:
    desired, manifest, compose, activation = _load_source_transition_state(plan)
    if activation is not None:
        _fail("REVIEWER_UPGRADE_SOURCE_CHANGED")
    if require_maintenance and desired["desired"] != "maintenance":
        raise UpgradeError("REVIEWER_UPGRADE_WAITING_MAINTENANCE")
    return desired, manifest, compose


def _validated_lock_binding(
    value: Any,
    path: Path,
    code: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != LOCK_FILE_BINDING_KEYS
        or any(
            type(value.get(key)) is not int
            for key in ("device", "inode", "mode", "uid")
        )
        or value.get("device", -1) < 0
        or value.get("inode", 0) <= 0
        or value.get("mode") != 0o600
        or value.get("uid") != os.geteuid()
        or value.get("path") != str(path)
    ):
        _fail(code)
    return dict(value)


def _processing_lock_epoch_files(transaction: Path) -> list[tuple[int, Path]]:
    try:
        entries = list(transaction.iterdir())
    except OSError as error:
        raise UpgradeError("UPGRADE_FINALIZE_LOCK_INVALID") from error
    found: dict[int, Path] = {}
    for entry in entries:
        if not entry.name.startswith(PROCESSING_LOCK_EPOCH_PREFIX):
            continue
        match = PROCESSING_LOCK_EPOCH_NAME.fullmatch(entry.name)
        if match is None:
            _fail("UPGRADE_FINALIZE_LOCK_INVALID")
        sequence = int(match.group(1), 10)
        if sequence <= 0 or sequence in found:
            _fail("UPGRADE_FINALIZE_LOCK_INVALID")
        found[sequence] = entry
    if found and sorted(found) != list(range(1, max(found) + 1)):
        _fail("UPGRADE_FINALIZE_LOCK_INVALID")
    return sorted(found.items())


def _load_processing_lock_epoch(
    transaction: Path,
    plan_document: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    finalize_plan = _validate_finalize_plan(
        plan["finalize"],
        plan["sealed_state_directory"],
        plan["candidate_repository_root"],
    )
    lock_file = _plan_path(finalize_plan["reconcile_bindings"]["lock_file"])
    initial = deepcopy(finalize_plan["processing_lock_epoch"])
    _validated_lock_binding(
        initial["lock_file_binding"],
        lock_file,
        "UPGRADE_FINALIZE_LOCK_INVALID",
    )
    previous = initial
    seen_boot_ids = {initial["boot_id"]}
    for sequence, path in _processing_lock_epoch_files(transaction):
        try:
            payload = reconciler._read_private(
                path,
                mode=0o600,
                code="UPGRADE_FINALIZE_LOCK_INVALID",
            )
            value = journal.parse_canonical_json(payload)
        except (journal.JournalError, reconciler.ReconcileError) as error:
            raise UpgradeError("UPGRADE_FINALIZE_LOCK_INVALID") from error
        if (
            not isinstance(value, dict)
            or set(value) != PROCESSING_LOCK_EPOCH_KEYS
            or value.get("contract_version")
            != PROCESSING_LOCK_EPOCH_CONTRACT
            or value.get("sequence") != sequence
            or value.get("plan_digest") != plan_document.get("plan_digest")
            or value.get("previous_epoch_digest")
            != previous.get("epoch_digest")
            or reconciler.BOOT_ID.fullmatch(str(value.get("boot_id"))) is None
            or value.get("boot_id") in seen_boot_ids
            or reconciler.DIGEST.fullmatch(str(value.get("epoch_digest")))
            is None
            or value.get("epoch_digest") != _epoch_digest(value)
        ):
            _fail("UPGRADE_FINALIZE_LOCK_INVALID")
        _validated_lock_binding(
            value.get("lock_file_binding"),
            lock_file,
            "UPGRADE_FINALIZE_LOCK_INVALID",
        )
        if payload != journal.canonical_json(value):
            _fail("UPGRADE_FINALIZE_LOCK_INVALID")
        previous = deepcopy(value)
        seen_boot_ids.add(value["boot_id"])
    return previous


def _publish_processing_lock_epoch(
    transaction: Path,
    plan_document: Mapping[str, Any],
    previous: Mapping[str, Any],
    *,
    boot_id: str,
    lock_file_binding: Mapping[str, Any],
) -> dict[str, Any]:
    sequence = int(previous["sequence"]) + 1
    if sequence <= 0 or sequence > 99_999_999:
        _fail("UPGRADE_FINALIZE_LOCK_INVALID")
    value: dict[str, Any] = {
        "boot_id": boot_id,
        "contract_version": PROCESSING_LOCK_EPOCH_CONTRACT,
        "epoch_digest": "",
        "lock_file_binding": dict(lock_file_binding),
        "plan_digest": plan_document["plan_digest"],
        "previous_epoch_digest": previous["epoch_digest"],
        "sequence": sequence,
    }
    value["epoch_digest"] = _epoch_digest(value)
    path = transaction / f"{PROCESSING_LOCK_EPOCH_PREFIX}{sequence:08d}.json"
    try:
        reconciler._atomic_private_write(
            path,
            journal.canonical_json(value),
            replace=False,
        )
    except (journal.JournalError, reconciler.ReconcileError) as error:
        raise UpgradeError("UPGRADE_FINALIZE_LOCK_INVALID") from error
    loaded = _load_processing_lock_epoch(transaction, plan_document, plan_document["plan"])
    if loaded != value:
        _fail("UPGRADE_FINALIZE_LOCK_INVALID")
    return loaded


def _reconcile_processing_lock_epoch(
    transaction: Path,
    plan_document: Mapping[str, Any],
    plan: Mapping[str, Any],
    descriptor: int,
) -> dict[str, Any]:
    finalize_plan = plan["finalize"]
    lock_file = _plan_path(finalize_plan["reconcile_bindings"]["lock_file"])
    try:
        observed = reconciler._validate_lock_descriptor(descriptor, lock_file)
    except reconciler.ReconcileError as error:
        raise UpgradeError("UPGRADE_FINALIZE_LOCK_INVALID") from error
    observed = _validated_lock_binding(
        observed,
        lock_file,
        "UPGRADE_FINALIZE_LOCK_INVALID",
    )
    current_boot_id = _current_boot_id("UPGRADE_FINALIZE_LOCK_INVALID")
    current_epoch = _load_processing_lock_epoch(
        transaction,
        plan_document,
        plan,
    )
    if current_epoch["boot_id"] == current_boot_id:
        if not reconciler._record_matches_binding(
            observed,
            current_epoch["lock_file_binding"],
        ):
            _fail("UPGRADE_FINALIZE_LOCK_INVALID")
        return dict(current_epoch["lock_file_binding"])
    published = _publish_processing_lock_epoch(
        transaction,
        plan_document,
        current_epoch,
        boot_id=current_boot_id,
        lock_file_binding=observed,
    )
    if not reconciler._record_matches_binding(
        observed,
        published["lock_file_binding"],
    ):
        _fail("UPGRADE_FINALIZE_LOCK_INVALID")
    return dict(published["lock_file_binding"])


@contextmanager
def _upgrade_serialization_lock(
    state_parent: Path,
    serial_lock_file: Path | None,
    *,
    expected_binding: Mapping[str, Any] | None = None,
    lock_descriptor: int | None = None,
) -> Iterator[tuple[int, dict[str, Any], Path]]:
    parent = reconciler._safe_directory(
        _canonical_path(state_parent, "REVIEWER_UPGRADE_SERIAL_LOCK_INVALID")
    )
    expected_path = parent / SERIAL_LOCK_FILE
    supplied = expected_path if serial_lock_file is None else serial_lock_file
    if (
        not isinstance(supplied, Path)
        or supplied != expected_path
        or not supplied.is_absolute()
        or str(supplied).startswith("//")
        or any(part in {".", ".."} for part in supplied.parts)
    ):
        _fail("REVIEWER_UPGRADE_SERIAL_LOCK_INVALID")
    descriptor: int | None = None
    borrowed = lock_descriptor is not None
    try:
        if borrowed:
            if type(lock_descriptor) is not int or lock_descriptor < 0:
                _fail("REVIEWER_UPGRADE_SERIAL_LOCK_INVALID")
            descriptor = lock_descriptor
            try:
                flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
                if not flags & fcntl.FD_CLOEXEC:
                    _fail("REVIEWER_UPGRADE_SERIAL_LOCK_INVALID")
                reconciler._validate_lock_descriptor(descriptor, supplied)
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                reconciler._validate_lock_descriptor(descriptor, supplied)
            except UpgradeError:
                raise
            except BlockingIOError as error:
                raise UpgradeError(
                    "REVIEWER_UPGRADE_LOCK_CONTENDED"
                ) from error
            except (OSError, reconciler.ReconcileError) as error:
                raise UpgradeError(
                    "REVIEWER_UPGRADE_SERIAL_LOCK_INVALID"
                ) from error
        else:
            descriptor = reconciler._open_host_lock(supplied, create=False)
        binding = reconciler._validate_lock_descriptor(descriptor, supplied)
        binding = _validated_lock_binding(
            binding,
            supplied,
            "REVIEWER_UPGRADE_SERIAL_LOCK_INVALID",
        )
        if expected_binding is not None:
            sealed = _validated_lock_binding(
                expected_binding,
                supplied,
                "REVIEWER_UPGRADE_SERIAL_LOCK_INVALID",
            )
            if not reconciler._record_matches_binding(binding, sealed):
                _fail("REVIEWER_UPGRADE_SERIAL_LOCK_INVALID")
        yield descriptor, binding, supplied
    except UpgradeError:
        raise
    except reconciler.ReconcileError as error:
        if error.code == "RECONCILE_DEFERRED":
            raise UpgradeError("REVIEWER_UPGRADE_LOCK_CONTENDED") from error
        raise UpgradeError("REVIEWER_UPGRADE_SERIAL_LOCK_INVALID") from error
    finally:
        if descriptor is not None and not borrowed:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _prepare_serial_lock_file(path: Path) -> tuple[int, bool]:
    flags = (
        os.O_RDWR
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    created = False
    try:
        try:
            descriptor = os.open(
                path,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(path, flags)
        if created:
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        reconciler._validate_lock_descriptor(descriptor, path)
        return descriptor, created
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        raise


@contextmanager
def _deployment_lock(project: str, descriptor: int | None) -> Iterator[int]:
    owned = descriptor is None
    selected = (
        reconciler._host_lock(project)
        if owned
        else reconciler._adopt_host_lock(project, int(descriptor))
    )
    try:
        yield selected
    finally:
        if owned:
            reconciler._release_lock(selected)


@contextmanager
def _deployment_lock_holder(
    project: str,
    descriptor: int | None,
) -> Iterator[dict[str, Any]]:
    """Own mutable lock bookkeeping across systemd handoffs."""

    owned = descriptor is None
    selected = (
        reconciler._host_lock(project)
        if owned
        else reconciler._adopt_host_lock(project, int(descriptor))
    )
    holder = {"borrowed": int(not owned), "descriptor": selected}
    try:
        yield holder
    finally:
        current = holder.get("descriptor")
        if owned and current is not None:
            reconciler._release_lock(current)


def _processing_lock_callbacks(
    holder: dict[str, Any],
    project: str,
    lock_file: Path,
    expected_binding: Mapping[str, Any],
) -> finalize.CallerOwnedProcessingLock:
    if lock_file != reconciler._lock_path(project):
        _fail("UPGRADE_FINALIZE_LOCK_INVALID")
    try:
        observed = reconciler._validate_lock_descriptor(
            holder["descriptor"],
            lock_file,
        )
    except (KeyError, reconciler.ReconcileError) as error:
        raise UpgradeError("UPGRADE_FINALIZE_LOCK_INVALID") from error
    expected = dict(expected_binding)
    if (
        set(expected) != LOCK_FILE_BINDING_KEYS
        or not reconciler._record_matches_binding(observed, expected)
    ):
        _fail("UPGRADE_FINALIZE_LOCK_INVALID")

    def current_descriptor() -> int:
        try:
            descriptor = holder["descriptor"]
            observed = reconciler._validate_lock_descriptor(
                descriptor,
                lock_file,
            )
        except (KeyError, reconciler.ReconcileError) as error:
            raise manager.ManagerError(
                "UPGRADE_MANAGER_LOCK_HANDOFF_INVALID"
            ) from error
        if not reconciler._record_matches_binding(observed, expected):
            raise manager.ManagerError("UPGRADE_MANAGER_LOCK_HANDOFF_INVALID")
        return descriptor

    def handoff(action: Callable[[], None]) -> int:
        if not callable(action):
            raise manager.ManagerError("UPGRADE_MANAGER_LOCK_HANDOFF_INVALID")
        try:
            stale = holder.pop("descriptor")
            observed = reconciler._validate_lock_descriptor(stale, lock_file)
        except (KeyError, reconciler.ReconcileError) as error:
            raise manager.ManagerError(
                "UPGRADE_MANAGER_LOCK_HANDOFF_INVALID"
            ) from error
        if not reconciler._record_matches_binding(observed, expected):
            holder["descriptor"] = stale
            raise manager.ManagerError("UPGRADE_MANAGER_LOCK_HANDOFF_INVALID")
        reconciler._release_lock(stale)
        try:
            action()
        finally:
            try:
                replacement = reconciler._open_host_lock(lock_file, create=False)
                rebound = reconciler._validate_lock_descriptor(
                    replacement,
                    lock_file,
                )
                if not reconciler._record_matches_binding(rebound, expected):
                    reconciler._release_lock(replacement)
                    raise manager.ManagerError(
                        "UPGRADE_MANAGER_LOCK_HANDOFF_INVALID"
                    )
                holder["descriptor"] = replacement
            except manager.ManagerError:
                raise
            except reconciler.ReconcileError as error:
                if error.code == "RECONCILE_DEFERRED":
                    raise
                raise manager.ManagerError(
                    "UPGRADE_MANAGER_LOCK_HANDOFF_INVALID"
                ) from error
        return holder["descriptor"]

    return finalize.CallerOwnedProcessingLock(
        current_descriptor=current_descriptor,
        handoff=handoff,
    )


def _image_id(
    manifest: Mapping[str, Any],
    runner: Runner,
    image_ref: str,
) -> str:
    payload = runner(
        [
            *reconciler._docker_prefix(manifest),
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            image_ref,
        ],
        timeout=30,
    )
    values = reconciler._lines(
        payload,
        reconciler.DIGEST,
        "REVIEWER_UPGRADE_CANDIDATE_INVALID",
    )
    if len(values) != 1:
        _fail("REVIEWER_UPGRADE_CANDIDATE_INVALID")
    return values[0]


def _authority_root(value: Any) -> Path:
    if type(value) is not str:
        _fail("REVIEWER_UPGRADE_CANDIDATE_INVALID")
    path = Path(value)
    suffix = INGRESS_CONFIG_SUFFIX.parts
    if (
        not path.is_absolute()
        or str(path) != value
        or value.startswith("//")
        or any(part in {".", ".."} for part in path.parts)
        or any(
            character in upgrade_systemd.UNSAFE_SYSTEMD_PATH_CHARACTERS
            for character in value
        )
        or tuple(path.parts[-len(suffix) :]) != suffix
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_INVALID")
    root_parts = path.parts[: -len(suffix)]
    if not root_parts:
        _fail("REVIEWER_UPGRADE_CANDIDATE_INVALID")
    root = Path(*root_parts)
    if not root.is_absolute() or root == Path("/"):
        _fail("REVIEWER_UPGRADE_CANDIDATE_INVALID")
    return root


def _candidate_relocation(
    source_document: Mapping[str, Any],
    candidate_document: Mapping[str, Any],
) -> tuple[str, str, Path, Path]:
    try:
        source = source_document["services"]["reviewer"]["image"]
        candidate = candidate_document["services"]["reviewer"]["image"]
        source_ingress = source_document["configs"]["tacua_loopback_ingress"]
        candidate_ingress = candidate_document["configs"][
            "tacua_loopback_ingress"
        ]
        source_root = _authority_root(source_ingress["file"])
        candidate_root = _authority_root(candidate_ingress["file"])
    except (KeyError, TypeError) as error:
        raise UpgradeError("REVIEWER_UPGRADE_CANDIDATE_INVALID") from error
    if (
        not isinstance(source, str)
        or not isinstance(candidate, str)
        or source == candidate
        or REVIEWER_TAG.fullmatch(candidate) is None
        or candidate.rsplit(":", 1)[1].lower() == "latest"
        or source_root == candidate_root
    ):
        _fail("REVIEWER_UPGRADE_CANDIDATE_INVALID")
    expected = deepcopy(source_document)
    expected["services"]["reviewer"]["image"] = candidate
    expected["configs"]["tacua_loopback_ingress"]["file"] = str(
        candidate_root / INGRESS_CONFIG_SUFFIX
    )
    for service in ("backend", "reviewer"):
        try:
            source_service = source_document["services"][service]
            candidate_service = candidate_document["services"][service]
        except (KeyError, TypeError) as error:
            raise UpgradeError(
                "REVIEWER_UPGRADE_CANDIDATE_INVALID"
            ) from error
        if not isinstance(source_service, dict) or not isinstance(
            candidate_service,
            dict,
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_INVALID")
        source_has_build = "build" in source_service
        candidate_has_build = "build" in candidate_service
        if source_has_build != candidate_has_build:
            _fail("REVIEWER_UPGRADE_CANDIDATE_INVALID")
        if not source_has_build:
            continue
        source_build = source_service["build"]
        candidate_build = candidate_service["build"]
        if (
            not isinstance(source_build, dict)
            or not isinstance(candidate_build, dict)
            or source_build.get("context") != str(source_root)
            or candidate_build.get("context") != str(candidate_root)
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_INVALID")
        expected["services"][service]["build"]["context"] = str(
            candidate_root
        )
    if candidate_document != expected:
        _fail("REVIEWER_UPGRADE_CANDIDATE_INVALID")
    return source, candidate, source_root, candidate_root


def _prepare_live_preconditions(
    desired: Mapping[str, Any],
    manifest: Mapping[str, Any],
    compose: Path,
    runner: Runner,
) -> dict[str, Any]:
    if desired["desired"] != "running":
        _fail("REVIEWER_UPGRADE_RUNNING_REQUIRED")
    reconciler._refuse_recovery_journal(manifest)
    if reconciler._daemon_projection(manifest, runner) != manifest["daemon"]:
        _fail("REVIEWER_UPGRADE_DAEMON_DRIFT")
    deployment, healthy = reconciler._inspect_deployment(
        manifest,
        compose,
        runner,
    )
    if not healthy:
        _fail("REVIEWER_UPGRADE_HEALTH_FAILED")
    _status, active = reconciler._tailnet_state(manifest, compose, runner)
    if not active:
        _fail("REVIEWER_UPGRADE_PUBLIC_PATH_INVALID")
    reconciler._smoke(manifest, public=False)
    reconciler._smoke(manifest, public=True)
    return deployment


def _inhibitor_document(
    project: str,
    plan_digest: str,
) -> dict[str, str]:
    document = {
        "contract_version": INHIBITOR_CONTRACT,
        "inhibitor_digest": "",
        "plan_digest": plan_digest,
        "project": project,
    }
    document["inhibitor_digest"] = reconciler._document_digest(
        document,
        "inhibitor_digest",
    )
    return document


def _validate_inhibitor_document(value: Any) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {"contract_version", "inhibitor_digest", "plan_digest", "project"}
        or value.get("contract_version") != INHIBITOR_CONTRACT
        or reconciler.PROJECT.fullmatch(str(value.get("project"))) is None
        or reconciler.DIGEST.fullmatch(str(value.get("plan_digest"))) is None
        or value.get("inhibitor_digest")
        != reconciler._document_digest(value, "inhibitor_digest")
    ):
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
    return dict(value)


def _inhibitor_path(manifest: Mapping[str, Any]) -> Path:
    parent = reconciler._safe_directory(Path(manifest["operation_directory"]))
    operation = parent / f"tacua-compose-processing-{manifest['project']}"
    if operation.parent != parent:
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
    return operation


def _load_inhibitor(
    operation: Path,
    expected: Mapping[str, str],
) -> dict[str, str]:
    operation = reconciler._safe_directory(operation)
    try:
        entries = {entry.name for entry in operation.iterdir()}
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_INHIBITOR_INVALID") from error
    if entries != {INHIBITOR_FILE}:
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
    payload = reconciler._read_private(
        operation / INHIBITOR_FILE,
        mode=0o600,
        code="REVIEWER_UPGRADE_INHIBITOR_INVALID",
    )
    try:
        value = journal.parse_canonical_json(payload)
    except journal.JournalError as error:
        raise UpgradeError("REVIEWER_UPGRADE_INHIBITOR_INVALID") from error
    inhibitor = _validate_inhibitor_document(value)
    if inhibitor != expected or payload != journal.canonical_json(inhibitor):
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
    return inhibitor


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


def _exact_linked_payload(
    path: Path,
    expected: bytes,
    *,
    links: set[int],
) -> os.stat_result:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        lexical = path.lstat()
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lexical.st_mode)
            or stat.S_ISLNK(lexical.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink not in links
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != len(expected)
            or (lexical.st_dev, lexical.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
        payload = bytearray()
        while len(payload) < len(expected):
            block = os.read(descriptor, len(expected) - len(payload))
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            bytes(payload) != expected
            or _metadata_tuple(before) != _metadata_tuple(after)
            or _metadata_tuple(after) != _metadata_tuple(current)
        ):
            _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
        return after
    except UpgradeError:
        raise
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_INHIBITOR_INVALID") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _repair_inhibitor_publication(
    operation: Path,
    entries: set[str],
    expected: bytes,
) -> set[str]:
    """Repair only the two exact hard-link publication crash states."""

    final = operation / INHIBITOR_FILE
    staging = operation / INHIBITOR_STAGING_FILE
    if entries == {INHIBITOR_STAGING_FILE}:
        _exact_linked_payload(staging, expected, links={1})
        try:
            staging.unlink()
            reconciler._fsync_directory(operation)
        except OSError as error:
            raise UpgradeError("REVIEWER_UPGRADE_INHIBITOR_INVALID") from error
        return set()
    if entries == {INHIBITOR_FILE, INHIBITOR_STAGING_FILE}:
        final_metadata = _exact_linked_payload(final, expected, links={2})
        staging_metadata = _exact_linked_payload(staging, expected, links={2})
        if (final_metadata.st_dev, final_metadata.st_ino) != (
            staging_metadata.st_dev,
            staging_metadata.st_ino,
        ):
            _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
        try:
            staging.unlink()
            reconciler._fsync_directory(operation)
        except OSError as error:
            raise UpgradeError("REVIEWER_UPGRADE_INHIBITOR_INVALID") from error
        _exact_linked_payload(final, expected, links={1})
        return {INHIBITOR_FILE}
    return entries


def _publish_inhibitor(operation: Path, payload: bytes) -> None:
    final = operation / INHIBITOR_FILE
    staging = operation / INHIBITOR_STAGING_FILE
    if (
        final.exists()
        or final.is_symlink()
        or staging.exists()
        or staging.is_symlink()
    ):
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
    try:
        _write_private_staging(staging, payload)
        _exact_linked_payload(staging, payload, links={1})
        os.link(staging, final, follow_symlinks=False)
        reconciler._fsync_directory(operation)
        staging.unlink()
        reconciler._fsync_directory(operation)
        _exact_linked_payload(final, payload, links={1})
    except UpgradeError as error:
        raise UpgradeError("REVIEWER_UPGRADE_INHIBITOR_INVALID") from error
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_INHIBITOR_INVALID") from error


def _operation_directory_binding(operation: Path) -> dict[str, int]:
    try:
        if operation.resolve(strict=True) != operation:
            _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
        metadata = operation.lstat()
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_INHIBITOR_INVALID") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
    return {
        "device": metadata.st_dev,
        "gid": metadata.st_gid,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
    }


def _validate_operation_directory_binding(value: Any) -> dict[str, int]:
    if (
        not isinstance(value, dict)
        or set(value) != {"device", "gid", "inode", "mode", "uid"}
        or any(type(value.get(key)) is not int for key in value)
        or value.get("device", -1) < 0
        or value.get("inode", 0) <= 0
        or value.get("gid", -1) < 0
        or value.get("uid") != os.geteuid()
        or value.get("mode") != 0o700
    ):
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
    return dict(value)


def _validate_bound_operation_directory(
    operation: Path,
    expected: Mapping[str, int],
) -> None:
    binding = _validate_operation_directory_binding(expected)
    if _operation_directory_binding(operation) != binding:
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")


def _quiescing_details(
    state: str,
    operation: Path,
    *,
    binding: Mapping[str, int] | None = None,
    inhibitor: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "gate_state": state,
        "inhibitor": None if inhibitor is None else dict(inhibitor),
        "operation_directory": str(operation),
        "operation_directory_binding": (
            None if binding is None else dict(binding)
        ),
    }


def _validate_quiescing_details(
    details: Mapping[str, Any],
    plan: Mapping[str, Any],
    plan_digest: str,
) -> None:
    if set(details) != {
        "gate_state",
        "inhibitor",
        "operation_directory",
        "operation_directory_binding",
    }:
        _fail()
    state = details.get("gate_state")
    operation = Path(str(details.get("operation_directory")))
    if (
        state not in {GATE_PENDING, GATE_DIRECTORY_BOUND, GATE_INHIBITOR_READY}
        or str(operation) != details.get("operation_directory")
        or not operation.is_absolute()
        or operation.name
        != f"tacua-compose-processing-{plan['project']}"
    ):
        _fail()
    binding = details.get("operation_directory_binding")
    inhibitor = details.get("inhibitor")
    if state == GATE_PENDING:
        if binding is not None or inhibitor is not None:
            _fail()
        return
    _validate_operation_directory_binding(binding)
    if state == GATE_DIRECTORY_BOUND:
        if inhibitor is not None:
            _fail()
        return
    expected = _inhibitor_document(plan["project"], plan_digest)
    if _validate_inhibitor_document(inhibitor) != expected:
        _fail()


def _processing_gate_from_quiescing(
    details: Mapping[str, Any],
    plan: Mapping[str, Any],
    plan_digest: str,
) -> dict[str, Any]:
    _validate_quiescing_details(details, plan, plan_digest)
    if details["gate_state"] != GATE_INHIBITOR_READY:
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
    return {
        "inhibitor": dict(details["inhibitor"]),
        "operation_directory": details["operation_directory"],
        "operation_directory_binding": dict(
            details["operation_directory_binding"]
        ),
    }


def _validate_processing_gate(
    value: Any,
    plan: Mapping[str, Any],
    plan_digest: str,
    *,
    manifest: Mapping[str, Any] | None = None,
    require_live: bool = False,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "inhibitor",
            "operation_directory",
            "operation_directory_binding",
        }
        or not isinstance(value.get("inhibitor"), dict)
        or not isinstance(value.get("operation_directory"), str)
        or not isinstance(value.get("operation_directory_binding"), dict)
    ):
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
    quiescing = _quiescing_details(
        GATE_INHIBITOR_READY,
        Path(str(value.get("operation_directory"))),
        binding=value.get("operation_directory_binding"),
        inhibitor=value.get("inhibitor"),
    )
    _validate_quiescing_details(quiescing, plan, plan_digest)
    record = _processing_gate_from_quiescing(quiescing, plan, plan_digest)
    operation = Path(record["operation_directory"])
    if manifest is not None and operation != _inhibitor_path(manifest):
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
    if require_live:
        _validate_bound_operation_directory(
            operation,
            record["operation_directory_binding"],
        )
        _load_inhibitor(operation, record["inhibitor"])
        _validate_bound_operation_directory(
            operation,
            record["operation_directory_binding"],
        )
    return record


def _drive_processing_gate(
    transaction: Path,
    plan_document: Mapping[str, Any],
    plan: Mapping[str, Any],
    progress: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    operation = _inhibitor_path(manifest)
    expected_inhibitor = _inhibitor_document(
        manifest["project"],
        plan_document["plan_digest"],
    )
    if progress["phase"] == PREPARED:
        progress = _checkpoint(
            transaction,
            plan_document,
            QUIESCING,
            _quiescing_details(GATE_PENDING, operation),
        )
    if progress["phase"] != QUIESCING:
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
    details = progress["details"]
    _validate_quiescing_details(
        details,
        plan,
        plan_document["plan_digest"],
    )
    if details["operation_directory"] != str(operation):
        _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
    if details["gate_state"] == GATE_PENDING:
        if operation.exists() or operation.is_symlink():
            _fail("REVIEWER_UPGRADE_INHIBITOR_AMBIGUOUS")
        try:
            operation.mkdir(mode=0o700)
            reconciler._fsync_directory(operation.parent)
        except OSError as error:
            raise UpgradeError("REVIEWER_UPGRADE_INHIBITOR_INVALID") from error
        binding = _operation_directory_binding(operation)
        progress = _checkpoint(
            transaction,
            plan_document,
            QUIESCING,
            _quiescing_details(
                GATE_DIRECTORY_BOUND,
                operation,
                binding=binding,
            ),
        )
        details = progress["details"]
    if details["gate_state"] == GATE_DIRECTORY_BOUND:
        binding = details["operation_directory_binding"]
        _validate_bound_operation_directory(operation, binding)
        inhibitor_payload = journal.canonical_json(expected_inhibitor)
        try:
            entries = {entry.name for entry in operation.iterdir()}
        except OSError as error:
            raise UpgradeError("REVIEWER_UPGRADE_INHIBITOR_INVALID") from error
        entries = _repair_inhibitor_publication(
            operation,
            entries,
            inhibitor_payload,
        )
        if not entries:
            _publish_inhibitor(operation, inhibitor_payload)
        elif entries != {INHIBITOR_FILE}:
            _fail("REVIEWER_UPGRADE_INHIBITOR_INVALID")
        _load_inhibitor(operation, expected_inhibitor)
        _validate_bound_operation_directory(operation, binding)
        reconciler._fsync_directory(operation)
        progress = _checkpoint(
            transaction,
            plan_document,
            QUIESCING,
            _quiescing_details(
                GATE_INHIBITOR_READY,
                operation,
                binding=binding,
                inhibitor=expected_inhibitor,
            ),
        )
        details = progress["details"]
    gate = _processing_gate_from_quiescing(
        details,
        plan,
        plan_document["plan_digest"],
    )
    gate = _validate_processing_gate(
        gate,
        plan,
        plan_document["plan_digest"],
        manifest=manifest,
        require_live=True,
    )
    return progress, gate


def _new_operation_id(candidate_digest: str) -> str:
    timestamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    return (
        f"reviewer-{timestamp}-{candidate_digest.removeprefix('sha256:')[:12]}-"
        f"{secrets.token_hex(4)}"
    )


def _create_transaction(
    upgrades: Path,
    operation_id: str | None,
    candidate_digest: str,
) -> tuple[str, Path]:
    supplied = operation_id is not None
    for _index in range(8):
        selected = operation_id or _new_operation_id(candidate_digest)
        if OPERATION_ID.fullmatch(selected) is None:
            _fail("REVIEWER_UPGRADE_INPUT_INVALID")
        path = upgrades / selected
        try:
            return selected, journal.create_transaction_directory(path)
        except journal.JournalError as error:
            if supplied or error.code != "REVIEWER_UPGRADE_JOURNAL_EXISTS":
                raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
            operation_id = None
    _fail("REVIEWER_UPGRADE_STATE_INVALID")


def _checkpoint(
    transaction: Path,
    plan_document: Mapping[str, Any],
    phase: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        progress = journal.checkpoint_progress(
            transaction,
            plan_document,
            phase,
            details,
        )
    except journal.JournalError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
    _validate_progress(
        progress,
        transaction,
        plan_document["plan"],
        plan_document["plan_digest"],
    )
    return progress


def _prepare_after_serial_preflight(
    state_directory: Path,
    candidate_compose: Path,
    *,
    unit_directory: Path,
    lock_file: Path,
    operation_directory: Path,
    serial_lock_file: Path | None = None,
    serial_lock_descriptor: int | None = None,
    runner: Runner | None = None,
    lock_descriptor: int | None = None,
    operation_id: str | None = None,
    expected_candidate_image_ref: str | None = None,
    expected_candidate_image_id: str | None = None,
) -> dict[str, Any]:
    """Prepare after a borrowed serial descriptor has been pre-acquired."""

    if (
        (expected_candidate_image_ref is None)
        != (expected_candidate_image_id is None)
        or (
            expected_candidate_image_ref is not None
            and (
                not isinstance(expected_candidate_image_ref, str)
                or not isinstance(expected_candidate_image_id, str)
                or REVIEWER_TAG.fullmatch(expected_candidate_image_ref) is None
                or expected_candidate_image_ref.rsplit(":", 1)[-1].lower()
                == "latest"
                or reconciler.DIGEST.fullmatch(expected_candidate_image_id)
                is None
            )
        )
    ):
        _fail("REVIEWER_UPGRADE_INPUT_INVALID")

    source = _canonical_path(state_directory, "REVIEWER_UPGRADE_INPUT_INVALID")
    initial_desired, initial_manifest, _initial_compose = (
        reconciler._load_bound_state(source)
    )
    selected_candidate = _canonical_path(
        candidate_compose,
        "REVIEWER_UPGRADE_INPUT_INVALID",
    )
    candidate_payload = reconciler._read_private(
        selected_candidate,
        mode=0o600,
        code="REVIEWER_UPGRADE_INPUT_INVALID",
    )
    candidate_document = reconciler._parse_json(
        candidate_payload,
        "REVIEWER_UPGRADE_INPUT_INVALID",
    )
    candidate_digest = reconciler._digest(candidate_payload)
    with _upgrade_serialization_lock(
        source.parent,
        serial_lock_file,
        lock_descriptor=serial_lock_descriptor,
    ) as (_serial_descriptor, serial_binding, _serial_path), _deployment_lock(
        initial_desired["project"], lock_descriptor
    ) as held_lock:
        upgrades = _ensure_upgrades_directory(source.parent)
        desired, manifest, compose = reconciler._load_bound_state(source)
        if desired != initial_desired or manifest != initial_manifest:
            _fail("REVIEWER_UPGRADE_SOURCE_CHANGED")
        if desired["desired"] != "running":
            _fail("REVIEWER_UPGRADE_RUNNING_REQUIRED")
        if reconciler._load_activation(source, desired) is not None:
            _fail("REVIEWER_UPGRADE_SOURCE_CHANGED")
        if _load_active(upgrades, optional=True) is not None:
            _fail("REVIEWER_UPGRADE_ACTIVE_EXISTS")
        selected_runner = runner or reconciler._runner_for_manifest(manifest)
        deployment = _prepare_live_preconditions(
            desired,
            manifest,
            compose,
            selected_runner,
        )
        source_document = reconciler._parse_json(
            reconciler._read_private(
                compose,
                mode=0o400,
                code="REVIEWER_UPGRADE_STATE_INVALID",
            ),
            "REVIEWER_UPGRADE_STATE_INVALID",
        )
        (
            _old_ref,
            candidate_ref,
            source_repository,
            candidate_repository,
        ) = _candidate_relocation(
            source_document,
            candidate_document,
        )
        candidate_id = _image_id(manifest, selected_runner, candidate_ref)
        if expected_candidate_image_ref is not None and (
            candidate_ref != expected_candidate_image_ref
            or candidate_id != expected_candidate_image_id
        ):
            _fail("REVIEWER_UPGRADE_CANDIDATE_REBOUND")

        selected_id, transaction = _create_transaction(
            upgrades,
            operation_id,
            candidate_digest,
        )

        reconciler._atomic_private_write(
            transaction / CANDIDATE_COMPOSE_FILE,
            candidate_payload,
            replace=False,
        )
        sealed_state = transaction / SEALED_STATE_DIRECTORY
        finalize_plan, unit_descriptors = _prepare_finalize_plan(
            transaction,
            sealed_state,
            manifest,
            candidate_repository_root=candidate_repository,
            unit_directory=unit_directory,
            lock_file=lock_file,
            operation_directory=operation_directory,
            lock_descriptor=held_lock,
        )
        plan_payload = {
            "backup": _backup_plan_payload(
                selected_id,
                source,
                manifest,
                source_document,
            ),
            "candidate_compose_digest": candidate_digest,
            "candidate_image_id": candidate_id,
            "candidate_image_ref": candidate_ref,
            "candidate_repository_root": str(candidate_repository),
            "finalize": finalize_plan,
            "operation_id": selected_id,
            "prepared_desired": desired,
            "project": manifest["project"],
            "source_compose_digest": manifest["compose_digest"],
            "source_generation": manifest["generation"],
            "source_manifest_digest": manifest["manifest_digest"],
            "source_repository_root": str(source_repository),
            "source_state_directory": str(source),
            "sealed_state_directory": str(sealed_state),
            "serial_lock": serial_binding,
            "unit_artifacts": unit_descriptors,
        }
        try:
            writer = getattr(journal, "write_immutable_plan", journal.write_plan)
            plan_document = writer(transaction, plan_payload)
        except journal.JournalError as error:
            raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
        _validate_plan(plan_document)
        deployment_digest = reconciler._digest(
            reconciler._canonical(deployment)
        )
        progress = _checkpoint(
            transaction,
            plan_document,
            PREPARED,
            {
                "prepared_desired": desired["desired"],
                "source_deployment_digest": deployment_digest,
                "source_reviewer_container_id": manifest["containers"]["reviewer"][
                    "id"
                ],
            },
        )
        _publish_active(upgrades, selected_id, plan_document["plan_digest"])
        progress, _gate = _drive_processing_gate(
            transaction,
            plan_document,
            plan_payload,
            progress,
            manifest,
        )
        return {
            "code": "REVIEWER_UPGRADE_PREPARED",
            "operation_id": selected_id,
            "phase": progress["phase"],
            "status": "quiescing",
        }


def prepare(
    state_directory: Path,
    candidate_compose: Path,
    *,
    unit_directory: Path,
    lock_file: Path,
    operation_directory: Path,
    serial_lock_file: Path | None = None,
    serial_lock_descriptor: int | None = None,
    runner: Runner | None = None,
    lock_descriptor: int | None = None,
    operation_id: str | None = None,
    expected_candidate_image_ref: str | None = None,
    expected_candidate_image_id: str | None = None,
) -> dict[str, Any]:
    """Durably prepare and publish an upgrade before deployment mutation.

    A supplied serial descriptor is caller-owned.  It is validated and
    non-blockingly acquired before state or candidate documents are read, then
    deliberately remains open and locked on both success and failure.
    """

    arguments = {
        "unit_directory": unit_directory,
        "lock_file": lock_file,
        "operation_directory": operation_directory,
        "serial_lock_file": serial_lock_file,
        "serial_lock_descriptor": serial_lock_descriptor,
        "runner": runner,
        "lock_descriptor": lock_descriptor,
        "operation_id": operation_id,
        "expected_candidate_image_ref": expected_candidate_image_ref,
        "expected_candidate_image_id": expected_candidate_image_id,
    }
    if serial_lock_descriptor is None:
        return _prepare_after_serial_preflight(
            state_directory,
            candidate_compose,
            **arguments,
        )
    if not isinstance(state_directory, Path):
        _fail("REVIEWER_UPGRADE_INPUT_INVALID")
    with _upgrade_serialization_lock(
        state_directory.parent,
        serial_lock_file,
        lock_descriptor=serial_lock_descriptor,
    ):
        return _prepare_after_serial_preflight(
            state_directory,
            candidate_compose,
            **arguments,
        )


def _optional_ids(payload: bytes, code: str) -> tuple[str, ...]:
    try:
        decoded = payload.decode("ascii", errors="strict")
    except UnicodeError as error:
        raise UpgradeError(code) from error
    values = tuple(line for line in decoded.splitlines() if line)
    if (
        len(values) != len(set(values))
        or any(reconciler.CONTAINER_ID.fullmatch(value) is None for value in values)
        or (not values and decoded not in {"", "\n"})
    ):
        raise UpgradeError(code)
    return values


def _healthy(document: Any) -> bool:
    if not isinstance(document, list) or len(document) != 1:
        return False
    state = document[0].get("State") if isinstance(document[0], dict) else None
    return (
        isinstance(state, dict)
        and state.get("Status") == "running"
        and state.get("Running") is True
        and isinstance(state.get("Health"), dict)
        and state["Health"].get("Status") == "healthy"
    )


def _candidate_labels(
    actual: Mapping[str, Any],
    source: Mapping[str, Any],
    candidate_id: str,
) -> bool:
    if set(actual) != set(source):
        return False
    for key, value in actual.items():
        if key == "com.docker.compose.config-hash":
            if not isinstance(value, str) or COMPOSE_HASH.fullmatch(value) is None:
                return False
        elif key == "com.docker.compose.image":
            if value != candidate_id:
                return False
        elif value != source[key]:
            return False
    return True


def _candidate_projection(
    actual: Mapping[str, Any],
    source: Mapping[str, Any],
    *,
    candidate_ref: str,
    candidate_id: str,
) -> bool:
    if set(actual) != set(source):
        return False
    actual_copy = deepcopy(actual)
    source_copy = deepcopy(source)
    labels = actual_copy.get("config", {}).get("Labels")
    source_labels = source_copy.get("config", {}).get("Labels")
    if not isinstance(labels, dict) or not isinstance(source_labels, dict):
        return False
    if not _candidate_labels(labels, source_labels, candidate_id):
        return False
    actual_copy["config"]["Labels"] = source_labels
    actual_copy["config"]["Image"] = source_copy["config"]["Image"]
    actual_copy["image_id"] = source_copy["image_id"]
    actual_copy["id"] = source_copy["id"]
    if actual.get("config", {}).get("Image") != candidate_ref:
        return False
    if actual.get("image_id") != candidate_id:
        return False
    if reconciler.CONTAINER_ID.fullmatch(str(actual.get("id"))) is None:
        return False
    return actual_copy == source_copy


def _resource_state(
    manifest: Mapping[str, Any],
    compose_document: Mapping[str, Any],
    runner: Runner,
    projections: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    docker = reconciler._docker_prefix(manifest)
    project = manifest["project"]
    resources: dict[str, Any] = {"networks": {}, "volumes": {}}
    for kind, command, network in (
        ("networks", "network", True),
        ("volumes", "volume", False),
    ):
        definitions = compose_document.get(kind)
        if not isinstance(definitions, dict) or not definitions:
            _fail("REVIEWER_UPGRADE_RESOURCE_DRIFT")
        for definition in definitions.values():
            name = definition.get("name") if isinstance(definition, dict) else None
            if not isinstance(name, str) or not name:
                _fail("REVIEWER_UPGRADE_RESOURCE_DRIFT")
            document = reconciler._json_command(
                runner,
                [*docker, command, "inspect", name],
                "REVIEWER_UPGRADE_RESOURCE_DRIFT",
            )
            resources[kind][name] = reconciler._resource_projection(
                document,
                network=network,
            )
        listed = set(
            reconciler._lines(
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
                reconciler.RESOURCE_NAME,
                "REVIEWER_UPGRADE_RESOURCE_DRIFT",
            )
        )
        if listed != set(resources[kind]):
            _fail("REVIEWER_UPGRADE_RESOURCE_DRIFT")
    expected = manifest["resources"]
    if (
        resources["volumes"] != expected["volumes"]
        or set(resources["networks"]) != set(expected["networks"])
    ):
        _fail("REVIEWER_UPGRADE_RESOURCE_DRIFT")
    expected_consumers = {name: set() for name in resources["networks"]}
    for projection in projections.values():
        for network_name in projection["networks"]:
            if network_name not in expected_consumers:
                _fail("REVIEWER_UPGRADE_RESOURCE_DRIFT")
            expected_consumers[network_name].add(projection["id"])
    for name, actual in resources["networks"].items():
        sealed = expected["networks"].get(name)
        if (
            not isinstance(sealed, dict)
            or set(actual) != set(sealed)
            or {
                key: value for key, value in actual.items() if key != "ContainerIDs"
            }
            != {
                key: value for key, value in sealed.items() if key != "ContainerIDs"
            }
            or actual.get("ContainerIDs") != sorted(expected_consumers[name])
        ):
            _fail("REVIEWER_UPGRADE_RESOURCE_DRIFT")
    try:
        state_volume = compose_document["volumes"]["tacua-state"]["name"]
    except (KeyError, TypeError) as error:
        raise UpgradeError("REVIEWER_UPGRADE_RESOURCE_DRIFT") from error
    consumers = reconciler._listed_container_ids(
        runner,
        docker,
        f"volume={state_volume}",
        "REVIEWER_UPGRADE_RESOURCE_DRIFT",
    )
    if consumers != {projections["backend"]["id"]}:
        _fail("REVIEWER_UPGRADE_RESOURCE_DRIFT")
    return resources


def _classify_deployment(
    manifest: Mapping[str, Any],
    candidate_compose: Path,
    candidate_document: Mapping[str, Any],
    plan: Mapping[str, Any],
    runner: Runner,
) -> dict[str, Any]:
    docker = reconciler._docker_prefix(manifest)
    prefix = reconciler._compose_prefix(manifest, candidate_compose)
    project_ids = reconciler._listed_container_ids(
        runner,
        docker,
        f"label=com.docker.compose.project={manifest['project']}",
        "REVIEWER_UPGRADE_CONTAINER_DRIFT",
    )
    projections: dict[str, Any] = {}
    health: dict[str, bool] = {}
    for service in reconciler.SERVICES:
        ids = _optional_ids(
            runner(
                [*prefix, "ps", "--no-trunc", "-aq", service],
                timeout=30,
            ),
            "REVIEWER_UPGRADE_CONTAINER_DRIFT",
        )
        if len(ids) != (0 if service == "reviewer" and not ids else 1):
            _fail("REVIEWER_UPGRADE_CONTAINER_DRIFT")
        if not ids:
            continue
        inspected = reconciler._json_command(
            runner,
            [*docker, "container", "inspect", ids[0]],
            "REVIEWER_UPGRADE_CONTAINER_DRIFT",
        )
        projections[service] = reconciler._container_projection(
            inspected,
            project=manifest["project"],
            service=service,
            published_port=manifest["published_port"],
        )
        health[service] = _healthy(inspected)
    if (
        set(projections) not in (
            {"backend", "ingress"},
            {"backend", "ingress", "reviewer"},
        )
        or project_ids != {projection["id"] for projection in projections.values()}
        or projections["backend"] != manifest["containers"]["backend"]
        or projections["ingress"] != manifest["containers"]["ingress"]
    ):
        _fail("REVIEWER_UPGRADE_CONTAINER_DRIFT")
    if "reviewer" not in projections:
        classification = ABSENT
    elif projections["reviewer"] == manifest["containers"]["reviewer"]:
        classification = OLD
    elif _candidate_projection(
        projections["reviewer"],
        manifest["containers"]["reviewer"],
        candidate_ref=plan["candidate_image_ref"],
        candidate_id=plan["candidate_image_id"],
    ):
        classification = CANDIDATE
    else:
        _fail("REVIEWER_UPGRADE_CONTAINER_DRIFT")
    resources = _resource_state(
        manifest,
        candidate_document,
        runner,
        projections,
    )
    deployment = {"containers": projections, "resources": resources}
    return {
        "classification": classification,
        "deployment": deployment,
        "deployment_digest": reconciler._digest(reconciler._canonical(deployment)),
        "health": health,
    }


def _validate_maintenance_runtime(
    manifest: Mapping[str, Any],
    compose: Path,
    runner: Runner,
    gate: Mapping[str, Any],
    plan: Mapping[str, Any],
    plan_digest: str,
) -> None:
    _validate_processing_gate(
        gate,
        plan,
        plan_digest,
        manifest=manifest,
        require_live=True,
    )
    reconciler._require_empty_tailnet_preactivation(manifest, compose, runner)
    if reconciler._daemon_projection(manifest, runner) != manifest["daemon"]:
        _fail("REVIEWER_UPGRADE_DAEMON_DRIFT")


def _maintenance_details(
    gate: Mapping[str, Any],
    desired: Mapping[str, Any],
    deployment: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "deployment_digest": reconciler._digest(
            reconciler._canonical(deployment)
        ),
        "maintenance_state_digest": desired["state_digest"],
        "processing_gate": dict(gate),
    }


def _prove_maintenance(
    plan: Mapping[str, Any],
    plan_digest: str,
    gate: Mapping[str, Any],
    desired: Mapping[str, Any],
    manifest: Mapping[str, Any],
    compose: Path,
    runner: Runner,
) -> dict[str, Any]:
    source = Path(plan["source_state_directory"])
    if (
        desired != _expected_maintenance(plan["prepared_desired"])
        or reconciler._load_activation(source, desired) is not None
    ):
        _fail("REVIEWER_UPGRADE_MAINTENANCE_INVALID")
    _validate_maintenance_runtime(
        manifest,
        compose,
        runner,
        gate,
        plan,
        plan_digest,
    )
    deployment, healthy = reconciler._inspect_deployment(
        manifest,
        compose,
        runner,
    )
    if not healthy:
        _fail("REVIEWER_UPGRADE_HEALTH_FAILED")
    reconciler._smoke(manifest, public=False)
    return _maintenance_details(gate, desired, deployment)


def _drive_maintenance(
    transaction: Path,
    plan_document: Mapping[str, Any],
    plan: Mapping[str, Any],
    progress: Mapping[str, Any],
    desired: Mapping[str, Any],
    manifest: Mapping[str, Any],
    compose: Path,
    activation: Mapping[str, Any] | None,
    runner: Runner,
    lock_descriptor: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Path]:
    if progress["phase"] == QUIESCING:
        gate = _processing_gate_from_quiescing(
            progress["details"],
            plan,
            plan_document["plan_digest"],
        )
    elif progress["phase"] == MAINTENANCE:
        gate = _validate_processing_gate(
            progress["details"].get("processing_gate"),
            plan,
            plan_document["plan_digest"],
        )
    else:
        _fail("REVIEWER_UPGRADE_MAINTENANCE_INVALID")
    gate = _validate_processing_gate(
        gate,
        plan,
        plan_document["plan_digest"],
        manifest=manifest,
        require_live=True,
    )
    if progress["phase"] == QUIESCING:
        source = Path(plan["source_state_directory"])
        if activation is None and desired["desired"] == "running":
            reconciler.set_maintenance(
                source,
                runner=runner,
                require_running=True,
                lock_descriptor=lock_descriptor,
            )
        elif activation is not None and activation.get("intent") == "maintenance":
            reconciler.reconcile(
                source,
                runner=runner,
                lock_descriptor=lock_descriptor,
            )
        elif not (activation is None and desired["desired"] == "maintenance"):
            _fail("REVIEWER_UPGRADE_MAINTENANCE_INVALID")
        desired, manifest, compose, activation = _load_source_transition_state(
            plan
        )
        if activation is not None:
            if activation.get("intent") != "maintenance":
                _fail("REVIEWER_UPGRADE_MAINTENANCE_INVALID")
            reconciler.reconcile(
                source,
                runner=runner,
                lock_descriptor=lock_descriptor,
            )
            desired, manifest, compose, activation = (
                _load_source_transition_state(plan)
            )
        if activation is not None:
            _fail("REVIEWER_UPGRADE_MAINTENANCE_INVALID")
        details = _prove_maintenance(
            plan,
            plan_document["plan_digest"],
            gate,
            desired,
            manifest,
            compose,
            runner,
        )
        progress = _checkpoint(
            transaction,
            plan_document,
            MAINTENANCE,
            details,
        )
    else:
        details = _prove_maintenance(
            plan,
            plan_document["plan_digest"],
            gate,
            desired,
            manifest,
            compose,
            runner,
        )
        if details != progress["details"]:
            _fail("REVIEWER_UPGRADE_MAINTENANCE_INVALID")
    return progress, desired, manifest, compose


def _drive_backup(
    transaction: Path,
    plan_document: Mapping[str, Any],
    plan: Mapping[str, Any],
    progress: Mapping[str, Any],
    desired: Mapping[str, Any],
    manifest: Mapping[str, Any],
    compose: Path,
    runner: Runner,
    backup_runner: BackupRunner,
) -> dict[str, Any]:
    if progress["phase"] not in {MAINTENANCE, BACKING_UP, BACKUP_READY}:
        _fail("REVIEWER_UPGRADE_BACKUP_INVALID")
    source = Path(plan["source_state_directory"])
    if (
        desired != _expected_maintenance(plan["prepared_desired"])
        or reconciler._load_activation(source, desired) is not None
    ):
        _fail("REVIEWER_UPGRADE_MAINTENANCE_INVALID")
    gate = _validate_processing_gate(
        progress["details"].get("processing_gate"),
        plan,
        plan_document["plan_digest"],
        manifest=manifest,
        require_live=True,
    )
    _validate_maintenance_runtime(
        manifest,
        compose,
        runner,
        gate,
        plan,
        plan_document["plan_digest"],
    )
    bindings = _live_backup_bindings(
        plan_document,
        plan,
        manifest,
        compose,
    )
    if progress["phase"] == MAINTENANCE:
        progress = _checkpoint(
            transaction,
            plan_document,
            BACKING_UP,
            {"processing_gate": gate},
        )
    if progress["phase"] == BACKING_UP:
        try:
            receipt = backup.run_backup_attempt(
                transaction,
                bindings,
                backup_runner,
            )
            receipt = backup.validate_backup_receipt(receipt, bindings)
        except backup.BackupError as error:
            raise UpgradeError(error.code) from error
        return _checkpoint(
            transaction,
            plan_document,
            BACKUP_READY,
            {
                "backup_receipt": receipt,
                "processing_gate": gate,
            },
        )
    try:
        expected = backup.validate_backup_receipt(
            progress["details"]["backup_receipt"],
            bindings,
        )
        observed = backup.run_backup_attempt(
            transaction,
            bindings,
            backup_runner,
        )
        observed = backup.validate_backup_receipt(observed, bindings)
    except backup.BackupError as error:
        raise UpgradeError(error.code) from error
    if observed != expected:
        _fail("REVIEWER_UPGRADE_BACKUP_CHANGED")
    return dict(progress)


def _ready_details(
    state: Mapping[str, Any],
    plan: Mapping[str, Any],
    gate: Mapping[str, Any],
) -> dict[str, Any]:
    reviewer = state["deployment"]["containers"].get("reviewer")
    if (
        state["classification"] != CANDIDATE
        or not isinstance(reviewer, dict)
        or reviewer.get("image_id") != plan["candidate_image_id"]
    ):
        _fail("REVIEWER_UPGRADE_CONTAINER_DRIFT")
    return {
        "candidate_container_id": reviewer["id"],
        "candidate_image_id": plan["candidate_image_id"],
        "deployment_digest": state["deployment_digest"],
        "processing_gate": dict(gate),
    }


def _require_ready_state(
    state: Mapping[str, Any],
    plan: Mapping[str, Any],
    gate: Mapping[str, Any],
    expected: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if (
        state["classification"] != CANDIDATE
        or set(state["health"]) != set(reconciler.SERVICES)
        or not all(state["health"].values())
    ):
        _fail("REVIEWER_UPGRADE_HEALTH_FAILED")
    details = _ready_details(state, plan, gate)
    if expected is not None and details != expected:
        _fail("REVIEWER_UPGRADE_DEPLOYMENT_CHANGED")
    return details


def _replace_reviewer(
    transaction: Path,
    plan_document: Mapping[str, Any],
    plan: Mapping[str, Any],
    progress: Mapping[str, Any],
    manifest: Mapping[str, Any],
    candidate_compose: Path,
    candidate_document: Mapping[str, Any],
    runner: Runner,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if progress["phase"] not in {BACKUP_READY, REPLACING}:
        _fail("REVIEWER_UPGRADE_BACKUP_REQUIRED")
    gate = _validate_processing_gate(
        progress["details"].get("processing_gate"),
        plan,
        plan_document["plan_digest"],
        manifest=manifest,
        require_live=True,
    )
    state = _classify_deployment(
        manifest,
        candidate_compose,
        candidate_document,
        plan,
        runner,
    )
    if not health_base_ok(state):
        _fail("REVIEWER_UPGRADE_HEALTH_FAILED")
    if progress["phase"] == BACKUP_READY and state["classification"] == ABSENT:
        _fail("REVIEWER_UPGRADE_CONTAINER_DRIFT")
    progress = _checkpoint(
        transaction,
        plan_document,
        REPLACING,
        {
            "candidate_image_id": plan["candidate_image_id"],
            "initial_classification": state["classification"],
            "processing_gate": gate,
        },
    )
    if state["classification"] == OLD and all(state["health"].values()):
        reconciler._smoke(manifest, public=False)
    if state["classification"] != CANDIDATE or not all(state["health"].values()):
        if _image_id(manifest, runner, plan["candidate_image_ref"]) != plan[
            "candidate_image_id"
        ]:
            _fail("REVIEWER_UPGRADE_CANDIDATE_REBOUND")
        progress = _checkpoint(
            transaction,
            plan_document,
            REPLACING,
            {
                "candidate_image_id": plan["candidate_image_id"],
                "initial_classification": state["classification"],
                "processing_gate": gate,
            },
        )
        runner(
            [
                *reconciler._compose_prefix(manifest, candidate_compose),
                "up",
                "-d",
                "--no-deps",
                "--no-build",
                "--pull",
                "never",
                "reviewer",
            ],
            timeout=120,
        )
        for index in range(HEALTH_ATTEMPTS):
            state = _classify_deployment(
                manifest,
                candidate_compose,
                candidate_document,
                plan,
                runner,
            )
            if (
                state["classification"] == CANDIDATE
                and health_base_ok(state)
                and all(state["health"].values())
            ):
                break
            if index + 1 < HEALTH_ATTEMPTS:
                time.sleep(HEALTH_INTERVAL_SECONDS)
        else:
            _fail("REVIEWER_UPGRADE_HEALTH_FAILED")
    details = _require_ready_state(state, plan, gate)
    if _image_id(manifest, runner, plan["candidate_image_ref"]) != plan[
        "candidate_image_id"
    ]:
        _fail("REVIEWER_UPGRADE_CANDIDATE_REBOUND")
    reconciler._smoke(manifest, public=False)
    progress = _checkpoint(
        transaction,
        plan_document,
        REVIEWER_READY,
        details,
    )
    return progress, state


def health_base_ok(state: Mapping[str, Any]) -> bool:
    return state["health"].get("backend") is True and state["health"].get(
        "ingress"
    ) is True


def _attempt_record(transaction: Path, number: int) -> dict[str, Any]:
    return {
        "generation": f"reviewer-upgrade-{number}",
        "number": number,
        "path": str(transaction / f"seal-attempt-{number}"),
    }


def _validate_attempts(
    details: Mapping[str, Any],
    transaction: Path,
) -> tuple[list[dict[str, Any]], list[int], int | None]:
    attempts = details.get("attempts")
    quarantined = details.get("quarantined_attempts")
    active = details.get("active_attempt")
    if (
        not isinstance(attempts, list)
        or len(attempts) > MAX_SEAL_ATTEMPTS
        or not isinstance(quarantined, list)
        or any(type(number) is not int for number in quarantined)
        or quarantined != sorted(set(quarantined))
        or (active is not None and type(active) is not int)
    ):
        _fail()
    for index, attempt in enumerate(attempts, start=1):
        if attempt != _attempt_record(transaction, index):
            _fail()
    numbers = list(range(1, len(attempts) + 1))
    if (
        any(number not in numbers for number in quarantined)
        or active in quarantined
        or (active is not None and active not in numbers)
    ):
        _fail()
    return list(attempts), list(quarantined), active


def _sealing_details(
    ready: Mapping[str, Any],
    attempts: Sequence[Mapping[str, Any]],
    quarantined: Sequence[int],
    active: int | None,
    sealed_state_directory: str,
) -> dict[str, Any]:
    return {
        "active_attempt": active,
        "attempts": list(attempts),
        "candidate_container_id": ready["candidate_container_id"],
        "deployment_digest": ready["deployment_digest"],
        "quarantined_attempts": list(quarantined),
        "sealed_state_directory": sealed_state_directory,
        "processing_gate": dict(ready["processing_gate"]),
    }


def _validated_finalization_receipt(
    value: Any,
    kind: str,
    plan: Mapping[str, Any],
    gate: Mapping[str, Any],
) -> dict[str, Any]:
    contracts = {
        "promotion": ("promote_target_maintenance", "maintenance_ready"),
        "activation": ("activate_target", "running_gate_held"),
        "gate_removal": ("remove_processing_gate", "gate_absent"),
        "scheduled": (
            "prove_later_scheduled_reconcile",
            "scheduled_reconcile_proven",
        ),
    }
    if kind not in contracts:
        _fail("UPGRADE_FINALIZE_RECEIPT_INVALID")
    operation, status = contracts[kind]
    receipt = _validate_finalize_receipt(
        value,
        operation=operation,
        status=status,
        project=plan["project"],
    )
    details = receipt["details"]
    if kind == "promotion":
        if (
            set(details) != {"target_unit_digests"}
            or not isinstance(details["target_unit_digests"], dict)
            or set(details["target_unit_digests"])
            != set(upgrade_systemd.UNIT_NAMES)
            or any(
                reconciler.DIGEST.fullmatch(str(digest)) is None
                for digest in details["target_unit_digests"].values()
            )
        ):
            _fail("UPGRADE_FINALIZE_RECEIPT_INVALID")
    elif kind in {"activation", "gate_removal"}:
        if details != {
            "inhibitor_digest": gate["inhibitor"]["inhibitor_digest"]
        }:
            _fail("UPGRADE_FINALIZE_RECEIPT_INVALID")
    elif (
        set(details) != {"invocation_id"}
        or manager.INVOCATION_ID.fullmatch(str(details["invocation_id"])) is None
    ):
        _fail("UPGRADE_FINALIZE_RECEIPT_INVALID")
    return receipt


def _validate_finalization_details(
    phase: str,
    details: Mapping[str, Any],
    plan: Mapping[str, Any],
    plan_digest: str,
) -> None:
    if phase == PROMOTING:
        if set(details) != {"processing_gate"}:
            _fail()
        _validate_processing_gate(details["processing_gate"], plan, plan_digest)
        return
    if phase == SCHEDULED_MAINTENANCE:
        if set(details) != {"processing_gate", "promotion_receipt"}:
            _fail()
        gate = _validate_processing_gate(
            details["processing_gate"], plan, plan_digest
        )
        _validated_finalization_receipt(
            details["promotion_receipt"], "promotion", plan, gate
        )
        return
    if phase == ACTIVATING:
        if set(details) != {
            "activation_receipt",
            "gate_removal_receipt",
            "processing_gate",
            "promotion_receipt",
            "substage",
        }:
            _fail()
        gate = _validate_processing_gate(
            details["processing_gate"], plan, plan_digest
        )
        promotion = _validated_finalization_receipt(
            details["promotion_receipt"], "promotion", plan, gate
        )
        substage = details.get("substage")
        activation = details.get("activation_receipt")
        removal = details.get("gate_removal_receipt")
        if substage == ACTIVATION_PENDING:
            if activation is not None or removal is not None:
                _fail()
        elif substage == ACTIVATION_RUNNING_GATE_HELD:
            if removal is not None:
                _fail()
            activation = _validated_finalization_receipt(
                activation, "activation", plan, gate
            )
        elif substage == ACTIVATION_GATE_ABSENT:
            activation = _validated_finalization_receipt(
                activation, "activation", plan, gate
            )
            removal = _validated_finalization_receipt(
                removal, "gate_removal", plan, gate
            )
        else:
            _fail()
        generations = {promotion["generation"]}
        if isinstance(activation, dict):
            generations.add(activation["generation"])
        if isinstance(removal, dict):
            generations.add(removal["generation"])
        if len(generations) != 1:
            _fail("UPGRADE_FINALIZE_RECEIPT_INVALID")
        return
    if phase == COMPLETE:
        if set(details) != {
            "activation_receipt",
            "gate_removal_receipt",
            "processing_gate",
            "promotion_receipt",
            "scheduled_receipt",
        }:
            _fail()
        gate = _validate_processing_gate(
            details["processing_gate"], plan, plan_digest
        )
        receipts = (
            _validated_finalization_receipt(
                details["promotion_receipt"], "promotion", plan, gate
            ),
            _validated_finalization_receipt(
                details["activation_receipt"], "activation", plan, gate
            ),
            _validated_finalization_receipt(
                details["gate_removal_receipt"], "gate_removal", plan, gate
            ),
            _validated_finalization_receipt(
                details["scheduled_receipt"], "scheduled", plan, gate
            ),
        )
        if len({receipt["generation"] for receipt in receipts}) != 1:
            _fail("UPGRADE_FINALIZE_RECEIPT_INVALID")
        return
    _fail()


def _validate_progress(
    progress: Mapping[str, Any],
    transaction: Path,
    plan: Mapping[str, Any],
    plan_digest: str,
) -> None:
    phase = progress.get("phase")
    details = progress.get("details")
    if phase not in SUPPORTED_PHASES or not isinstance(details, dict):
        _fail()
    if phase == PREPARED:
        if (
            set(details)
            != {
                "prepared_desired",
                "source_deployment_digest",
                "source_reviewer_container_id",
            }
            or details.get("prepared_desired")
            != plan["prepared_desired"]["desired"]
            or reconciler.DIGEST.fullmatch(
                str(details.get("source_deployment_digest"))
            )
            is None
            or reconciler.CONTAINER_ID.fullmatch(
                str(details.get("source_reviewer_container_id"))
            )
            is None
        ):
            _fail()
    elif phase == QUIESCING:
        _validate_quiescing_details(details, plan, plan_digest)
    elif phase == MAINTENANCE:
        if (
            set(details)
            != {
                "deployment_digest",
                "maintenance_state_digest",
                "processing_gate",
            }
            or reconciler.DIGEST.fullmatch(
                str(details.get("deployment_digest"))
            )
            is None
            or reconciler.DIGEST.fullmatch(
                str(details.get("maintenance_state_digest"))
            )
            is None
        ):
            _fail()
        _validate_processing_gate(
            details["processing_gate"],
            plan,
            plan_digest,
        )
    elif phase == BACKING_UP:
        if set(details) != {"processing_gate"}:
            _fail()
        _validate_processing_gate(
            details["processing_gate"],
            plan,
            plan_digest,
        )
    elif phase == BACKUP_READY:
        if set(details) != {"backup_receipt", "processing_gate"}:
            _fail()
        _validate_processing_gate(
            details["processing_gate"],
            plan,
            plan_digest,
        )
        bindings = _backup_bindings(
            {"plan_digest": plan_digest},
            plan,
        )
        try:
            backup.validate_backup_receipt(
                details["backup_receipt"],
                bindings,
            )
        except backup.BackupError as error:
            raise UpgradeError("REVIEWER_UPGRADE_BACKUP_INVALID") from error
    elif phase == REPLACING:
        if (
            set(details)
            != {
                "candidate_image_id",
                "initial_classification",
                "processing_gate",
            }
            or details.get("candidate_image_id") != plan["candidate_image_id"]
            or details.get("initial_classification") not in {OLD, ABSENT, CANDIDATE}
        ):
            _fail()
        _validate_processing_gate(
            details["processing_gate"],
            plan,
            plan_digest,
        )
    elif phase == REVIEWER_READY:
        if (
            set(details)
            != {
                "candidate_container_id",
                "candidate_image_id",
                "deployment_digest",
                "processing_gate",
            }
            or details.get("candidate_image_id") != plan["candidate_image_id"]
            or reconciler.CONTAINER_ID.fullmatch(
                str(details.get("candidate_container_id"))
            )
            is None
            or reconciler.DIGEST.fullmatch(str(details.get("deployment_digest")))
            is None
        ):
            _fail()
        _validate_processing_gate(
            details["processing_gate"],
            plan,
            plan_digest,
        )
    elif phase in {SEALING, SEALED_MAINTENANCE}:
        required = {
            "active_attempt",
            "attempts",
            "candidate_container_id",
            "deployment_digest",
            "quarantined_attempts",
            "sealed_state_directory",
            "processing_gate",
        }
        if (
            set(details) != required
            or reconciler.CONTAINER_ID.fullmatch(
                str(details.get("candidate_container_id"))
            )
            is None
            or reconciler.DIGEST.fullmatch(str(details.get("deployment_digest")))
            is None
            or details.get("sealed_state_directory")
            != plan["sealed_state_directory"]
        ):
            _fail()
        _validate_processing_gate(
            details["processing_gate"],
            plan,
            plan_digest,
        )
        attempts, quarantined, active = _validate_attempts(details, transaction)
        if phase == SEALED_MAINTENANCE and (
            active is None
            or active != len(attempts)
            or active in quarantined
        ):
            _fail()
    elif phase in {PROMOTING, SCHEDULED_MAINTENANCE, ACTIVATING, COMPLETE}:
        _validate_finalization_details(
            phase,
            details,
            plan,
            plan_digest,
        )
def _safe_attempt_directory(path: Path, transaction: Path) -> None:
    if path.parent != transaction:
        _fail()
    try:
        metadata = path.lstat()
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail()


def _fsync_recovered_directory_rename(
    transaction: Path,
    missing: Path,
    present: Path,
) -> None:
    if (
        missing.parent != transaction
        or present.parent != transaction
        or missing == present
    ):
        _fail("REVIEWER_UPGRADE_STATE_INVALID")
    _safe_attempt_directory(present, transaction)
    if missing.exists() or missing.is_symlink():
        _fail("REVIEWER_UPGRADE_STATE_INVALID")
    descriptor: int | None = None
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(transaction, flags)
        parent_before = os.fstat(descriptor)
        parent_path = transaction.lstat()
        present_before = present.lstat()
        parent_identity = (
            parent_before.st_dev,
            parent_before.st_ino,
            stat.S_IMODE(parent_before.st_mode),
            parent_before.st_uid,
            parent_before.st_gid,
        )
        present_identity = (
            present_before.st_dev,
            present_before.st_ino,
            stat.S_IMODE(present_before.st_mode),
            present_before.st_uid,
            present_before.st_gid,
        )
        if (
            not stat.S_ISDIR(parent_before.st_mode)
            or stat.S_ISLNK(parent_path.st_mode)
            or parent_identity
            != (
                parent_path.st_dev,
                parent_path.st_ino,
                stat.S_IMODE(parent_path.st_mode),
                parent_path.st_uid,
                parent_path.st_gid,
            )
            or parent_before.st_uid != os.geteuid()
            or stat.S_IMODE(parent_before.st_mode) != 0o700
            or not stat.S_ISDIR(present_before.st_mode)
            or stat.S_ISLNK(present_before.st_mode)
            or present_before.st_uid != os.geteuid()
            or stat.S_IMODE(present_before.st_mode) != 0o700
        ):
            _fail("REVIEWER_UPGRADE_STATE_INVALID")

        def prove() -> None:
            parent_opened = os.fstat(descriptor)
            parent_current = transaction.lstat()
            current = os.stat(
                present.name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            try:
                os.stat(
                    missing.name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                _fail("REVIEWER_UPGRADE_STATE_INVALID")
            if (
                parent_identity
                != (
                    parent_opened.st_dev,
                    parent_opened.st_ino,
                    stat.S_IMODE(parent_opened.st_mode),
                    parent_opened.st_uid,
                    parent_opened.st_gid,
                )
                or parent_identity
                != (
                    parent_current.st_dev,
                    parent_current.st_ino,
                    stat.S_IMODE(parent_current.st_mode),
                    parent_current.st_uid,
                    parent_current.st_gid,
                )
                or present_identity
                != (
                    current.st_dev,
                    current.st_ino,
                    stat.S_IMODE(current.st_mode),
                    current.st_uid,
                    current.st_gid,
                )
                or not stat.S_ISDIR(current.st_mode)
            ):
                _fail("REVIEWER_UPGRADE_STATE_INVALID")

        prove()
        os.fsync(descriptor)
        prove()
    except UpgradeError:
        raise
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _quarantine_attempt(
    transaction: Path,
    attempt: Mapping[str, Any],
) -> None:
    path = Path(attempt["path"])
    quarantine = transaction / f"quarantine-seal-attempt-{attempt['number']}"
    attempt_exists = path.exists() or path.is_symlink()
    quarantine_exists = quarantine.exists() or quarantine.is_symlink()
    if attempt_exists and quarantine_exists:
        _fail()
    if quarantine_exists:
        _fsync_recovered_directory_rename(
            transaction,
            path,
            quarantine,
        )
        return
    if not attempt_exists:
        _fail()
    _safe_attempt_directory(path, transaction)
    try:
        os.replace(path, quarantine)
        reconciler._fsync_directory(transaction)
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
    _safe_attempt_directory(quarantine, transaction)
    _fsync_recovered_directory_rename(
        transaction,
        path,
        quarantine,
    )


def _sealed_state_valid(
    path: Path,
    attempt: Mapping[str, Any],
    plan: Mapping[str, Any],
    source_manifest: Mapping[str, Any],
    ready: Mapping[str, Any],
    runner: Runner,
) -> bool:
    try:
        desired, manifest, compose = reconciler._load_bound_state(path)
        if (
            desired["desired"] != "maintenance"
            or reconciler._load_activation(path, desired) is not None
            or manifest["project"] != plan["project"]
            or manifest["generation"] != attempt["generation"]
            or manifest["compose_digest"] != plan["candidate_compose_digest"]
            or manifest["daemon"] != source_manifest["daemon"]
            or manifest["runtime"] != source_manifest["runtime"]
            or manifest["commands"] != source_manifest["commands"]
            or manifest["config"] != source_manifest["config"]
            or manifest["secret"] != source_manifest["secret"]
            or manifest["operation_directory"]
            != source_manifest["operation_directory"]
            or manifest["published_port"] != source_manifest["published_port"]
            or manifest["containers"]["reviewer"]["id"]
            != ready["candidate_container_id"]
            or manifest["containers"]["reviewer"]["image_id"]
            != plan["candidate_image_id"]
        ):
            return False
        deployment, healthy = reconciler._inspect_deployment(
            manifest,
            compose,
            runner,
        )
        return (
            healthy
            and reconciler._digest(reconciler._canonical(deployment))
            == ready["deployment_digest"]
        )
    except (reconciler.ReconcileError, OSError, KeyError, TypeError):
        return False


def _promote_sealed_attempt(
    transaction: Path,
    attempt: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> Path:
    source = Path(attempt["path"])
    destination = Path(plan["sealed_state_directory"])
    if source.parent != transaction or destination != transaction / SEALED_STATE_DIRECTORY:
        _fail()
    if destination.exists() or destination.is_symlink():
        _fail("REVIEWER_UPGRADE_SEALED_STATE_EXISTS")
    _safe_attempt_directory(source, transaction)
    try:
        os.rename(source, destination)
        reconciler._fsync_directory(transaction)
    except OSError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
    _fsync_recovered_directory_rename(
        transaction,
        source,
        destination,
    )
    return destination


def _seal_candidate(
    transaction: Path,
    plan_document: Mapping[str, Any],
    plan: Mapping[str, Any],
    progress: Mapping[str, Any],
    source_manifest: Mapping[str, Any],
    candidate_compose: Path,
    ready: Mapping[str, Any],
    runner: Runner,
    lock_descriptor: int,
    inhibitor: Mapping[str, str],
) -> dict[str, Any]:
    sealed_state = Path(plan["sealed_state_directory"])
    if progress["phase"] == REVIEWER_READY:
        progress = _checkpoint(
            transaction,
            plan_document,
            SEALING,
            _sealing_details(
                ready,
                [],
                [],
                None,
                plan["sealed_state_directory"],
            ),
        )
    attempts, quarantined, active = _validate_attempts(
        progress["details"],
        transaction,
    )
    if active is not None:
        attempt = attempts[active - 1]
        path = Path(attempt["path"])
        quarantine = transaction / f"quarantine-seal-attempt-{active}"
        if sealed_state.exists() or sealed_state.is_symlink():
            _fsync_recovered_directory_rename(
                transaction,
                path,
                sealed_state,
            )
            if not _sealed_state_valid(
                sealed_state,
                attempt,
                plan,
                source_manifest,
                ready,
                runner,
            ):
                _fail("REVIEWER_UPGRADE_SEALED_STATE_INVALID")
            return _checkpoint(
                transaction,
                plan_document,
                SEALED_MAINTENANCE,
                _sealing_details(
                    ready,
                    attempts,
                    quarantined,
                    active,
                    plan["sealed_state_directory"],
                ),
            )
        if path.exists() or path.is_symlink():
            if _sealed_state_valid(
                path,
                attempt,
                plan,
                source_manifest,
                ready,
                runner,
            ):
                sealed_state = _promote_sealed_attempt(
                    transaction,
                    attempt,
                    plan,
                )
                if not _sealed_state_valid(
                    sealed_state,
                    attempt,
                    plan,
                    source_manifest,
                    ready,
                    runner,
                ):
                    _fail("REVIEWER_UPGRADE_SEALED_STATE_INVALID")
                return _checkpoint(
                    transaction,
                    plan_document,
                    SEALED_MAINTENANCE,
                    _sealing_details(
                        ready,
                        attempts,
                        quarantined,
                        active,
                        plan["sealed_state_directory"],
                    ),
                )
            _quarantine_attempt(transaction, attempt)
            quarantined.append(active)
            active = None
            progress = _checkpoint(
                transaction,
                plan_document,
                SEALING,
                _sealing_details(
                    ready,
                    attempts,
                    quarantined,
                    active,
                    plan["sealed_state_directory"],
                ),
            )
        elif quarantine.exists() or quarantine.is_symlink():
            _fsync_recovered_directory_rename(
                transaction,
                path,
                quarantine,
            )
            if active not in quarantined:
                quarantined.append(active)
                quarantined.sort()
            active = None
            progress = _checkpoint(
                transaction,
                plan_document,
                SEALING,
                _sealing_details(
                    ready,
                    attempts,
                    quarantined,
                    active,
                    plan["sealed_state_directory"],
                ),
            )
        else:
            # The attempt path was journaled before calling seal and the crash
            # happened before seal created it.  Reuse that exact journaled path.
            pass
    if active is None:
        if len(attempts) >= MAX_SEAL_ATTEMPTS:
            _fail("REVIEWER_UPGRADE_SEAL_ATTEMPTS_EXHAUSTED")
        active = len(attempts) + 1
        attempt = _attempt_record(transaction, active)
        attempts.append(attempt)
        progress = _checkpoint(
            transaction,
            plan_document,
            SEALING,
            _sealing_details(
                ready,
                attempts,
                quarantined,
                active,
                plan["sealed_state_directory"],
            ),
        )
    else:
        attempt = attempts[active - 1]

    attempt_path = Path(attempt["path"])
    if attempt_path.exists() or attempt_path.is_symlink():
        # Only a complete valid attempt is accepted; this branch can be reached
        # after a same-process checkpoint race, so fail closed and let the next
        # invocation quarantine it.
        if not _sealed_state_valid(
            attempt_path,
            attempt,
            plan,
            source_manifest,
            ready,
            runner,
        ):
            _fail("REVIEWER_UPGRADE_SEAL_INCOMPLETE")
    else:
        args = SimpleNamespace(
            admin_secret_file=Path(source_manifest["secret"]["path"]),
            allow_mutable_image=True,
            compose_json=candidate_compose,
            config_file=Path(source_manifest["config"]["path"]),
            docker_service=source_manifest["commands"]["docker_service"],
            generation=attempt["generation"],
            maintenance=True,
            operation_directory=Path(source_manifest["operation_directory"]),
            project=source_manifest["project"],
            state_directory=attempt_path,
        )
        reconciler.seal(
            args,
            runner=runner,
            lock_descriptor=lock_descriptor,
            upgrade_inhibitor=inhibitor,
            expected_repository_root=_plan_path(
                plan["candidate_repository_root"]
            ),
        )
    if not _sealed_state_valid(
        attempt_path,
        attempt,
        plan,
        source_manifest,
        ready,
        runner,
    ):
        _fail("REVIEWER_UPGRADE_SEAL_INCOMPLETE")
    sealed_state = _promote_sealed_attempt(transaction, attempt, plan)
    if not _sealed_state_valid(
        sealed_state,
        attempt,
        plan,
        source_manifest,
        ready,
        runner,
    ):
        _fail("REVIEWER_UPGRADE_SEALED_STATE_INVALID")
    return _checkpoint(
        transaction,
        plan_document,
        SEALED_MAINTENANCE,
        _sealing_details(
            ready,
            attempts,
            quarantined,
            active,
            plan["sealed_state_directory"],
        ),
    )


def _activating_details(
    gate: Mapping[str, Any],
    promotion_receipt: Mapping[str, Any],
    substage: str,
    *,
    activation_receipt: Mapping[str, Any] | None = None,
    gate_removal_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "activation_receipt": (
            None if activation_receipt is None else dict(activation_receipt)
        ),
        "gate_removal_receipt": (
            None
            if gate_removal_receipt is None
            else dict(gate_removal_receipt)
        ),
        "processing_gate": dict(gate),
        "promotion_receipt": dict(promotion_receipt),
        "substage": substage,
    }


def _drive_finalization(
    transaction: Path,
    plan_document: Mapping[str, Any],
    plan: Mapping[str, Any],
    progress: Mapping[str, Any],
    gate: Mapping[str, Any],
    runner: Runner,
    lock_holder: dict[str, Any],
) -> dict[str, Any]:
    if lock_holder.get("borrowed", 0) != 0:
        _fail("UPGRADE_FINALIZE_LOCK_INVALID")
    if progress["phase"] == SEALED_MAINTENANCE:
        progress = _checkpoint(
            transaction,
            plan_document,
            PROMOTING,
            {"processing_gate": dict(gate)},
        )
    bindings = _finalize_bindings(
        transaction,
        plan,
        plan_document["plan_digest"],
        gate,
        lock_holder,
    )
    try:
        if progress["phase"] == PROMOTING:
            _descriptor, promotion_receipt = finalize.promote_target_maintenance(
                bindings,
                runner,
            )
            promotion_receipt = _validated_finalization_receipt(
                promotion_receipt,
                "promotion",
                plan,
                gate,
            )
            if promotion_receipt["details"]["target_unit_digests"] != (
                bindings.target_units.digests()
            ):
                _fail("UPGRADE_FINALIZE_RECEIPT_INVALID")
            progress = _checkpoint(
                transaction,
                plan_document,
                SCHEDULED_MAINTENANCE,
                {
                    "processing_gate": dict(gate),
                    "promotion_receipt": promotion_receipt,
                },
            )
        if progress["phase"] == SCHEDULED_MAINTENANCE:
            progress = _checkpoint(
                transaction,
                plan_document,
                ACTIVATING,
                _activating_details(
                    gate,
                    progress["details"]["promotion_receipt"],
                    ACTIVATION_PENDING,
                ),
            )
        if progress["phase"] == ACTIVATING:
            details = progress["details"]
            substage = details["substage"]
            if substage == ACTIVATION_PENDING:
                _descriptor, activation_receipt = finalize.activate_target(
                    bindings,
                    runner,
                )
                activation_receipt = _validated_finalization_receipt(
                    activation_receipt,
                    "activation",
                    plan,
                    gate,
                )
                progress = _checkpoint(
                    transaction,
                    plan_document,
                    ACTIVATING,
                    _activating_details(
                        gate,
                        details["promotion_receipt"],
                        ACTIVATION_RUNNING_GATE_HELD,
                        activation_receipt=activation_receipt,
                    ),
                )
                details = progress["details"]
                substage = details["substage"]
            if substage == ACTIVATION_RUNNING_GATE_HELD:
                _descriptor, gate_receipt = finalize.remove_processing_gate(
                    bindings
                )
                gate_receipt = _validated_finalization_receipt(
                    gate_receipt,
                    "gate_removal",
                    plan,
                    gate,
                )
                progress = _checkpoint(
                    transaction,
                    plan_document,
                    ACTIVATING,
                    _activating_details(
                        gate,
                        details["promotion_receipt"],
                        ACTIVATION_GATE_ABSENT,
                        activation_receipt=details["activation_receipt"],
                        gate_removal_receipt=gate_receipt,
                    ),
                )
                details = progress["details"]
                substage = details["substage"]
            if substage == ACTIVATION_GATE_ABSENT:
                _descriptor, scheduled_receipt = (
                    finalize.prove_later_scheduled_reconcile(
                        bindings,
                        runner,
                        deadline_seconds=SCHEDULED_RECONCILE_DEADLINE_SECONDS,
                    )
                )
                scheduled_receipt = _validated_finalization_receipt(
                    scheduled_receipt,
                    "scheduled",
                    plan,
                    gate,
                )
                progress = _checkpoint(
                    transaction,
                    plan_document,
                    COMPLETE,
                    {
                        "activation_receipt": details["activation_receipt"],
                        "gate_removal_receipt": details[
                            "gate_removal_receipt"
                        ],
                        "processing_gate": dict(gate),
                        "promotion_receipt": details["promotion_receipt"],
                        "scheduled_receipt": scheduled_receipt,
                    },
                )
    except finalize.FinalizeError as error:
        raise UpgradeError(error.code) from error
    if progress["phase"] != COMPLETE:
        _fail()
    try:
        receipt = journal.load_receipt(transaction, plan_document)
        if receipt is None:
            receipt = journal.write_receipt(
                transaction,
                plan_document,
                {"finalization": progress["details"]},
            )
        if receipt["details"] != {"finalization": progress["details"]}:
            _fail("REVIEWER_UPGRADE_STATE_INVALID")
    except journal.JournalError as error:
        raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error
    return dict(progress)


def _clear_active(
    upgrades: Path,
    expected: Mapping[str, str],
) -> None:
    with _active_directory_lock(upgrades):
        current = _load_active_locked(upgrades, optional=False)
        if current != expected:
            _fail("REVIEWER_UPGRADE_STATE_CHANGED")
        try:
            (upgrades / ACTIVE_FILE).unlink()
            reconciler._fsync_directory(upgrades)
        except OSError as error:
            raise UpgradeError("REVIEWER_UPGRADE_STATE_INVALID") from error


def _resume_serialized(
    state_parent: Path,
    *,
    unit_directory: Path | None = None,
    lock_file: Path | None = None,
    operation_directory: Path | None = None,
    runner: Runner | None = None,
    backup_runner: BackupRunner | None = None,
    lock_descriptor: int | None = None,
    _defer_backup_for_test: bool = False,
    _defer_finalization_for_test: bool = False,
    _skip_processing_lock_binding_for_test: bool = False,
    _serial_binding: Mapping[str, Any],
) -> dict[str, Any]:
    upgrades = _existing_upgrades_directory(state_parent)
    if upgrades is None:
        return {"code": "REVIEWER_UPGRADE_IDLE", "status": "idle"}
    initial_active = _load_active(upgrades, optional=True)
    if initial_active is None:
        _fsync_validated_directory(upgrades)
        if _load_active(upgrades, optional=True) is not None:
            _fail("REVIEWER_UPGRADE_STATE_CHANGED")
        return {"code": "REVIEWER_UPGRADE_IDLE", "status": "idle"}
    transaction, plan_document, plan, initial_progress = _load_transaction(
        upgrades,
        initial_active,
    )
    sealed_serial = _validated_lock_binding(
        plan["serial_lock"],
        Path(plan["source_state_directory"]).parent / SERIAL_LOCK_FILE,
        "REVIEWER_UPGRADE_SERIAL_LOCK_INVALID",
    )
    if not reconciler._record_matches_binding(_serial_binding, sealed_serial):
        _fail("REVIEWER_UPGRADE_SERIAL_LOCK_INVALID")
    _initial_desired, initial_manifest, _initial_compose, _initial_activation = (
        _load_source_transition_state(plan)
    )
    if initial_manifest["project"] != plan["project"]:
        _fail()
    _validate_finalize_plan(
        plan["finalize"],
        plan["sealed_state_directory"],
        plan["candidate_repository_root"],
        initial_manifest,
    )
    _bind_resume_abi(
        plan,
        unit_directory=unit_directory,
        lock_file=lock_file,
        operation_directory=operation_directory,
    )

    with _deployment_lock_holder(plan["project"], lock_descriptor) as lock_holder:
        if not _skip_processing_lock_binding_for_test:
            lock_holder["expected_binding"] = _reconcile_processing_lock_epoch(
                transaction,
                plan_document,
                plan,
                lock_holder["descriptor"],
            )
        else:
            lock_holder["expected_binding"] = deepcopy(
                plan["finalize"]["lock_file_binding"]
            )
        active = _load_active(upgrades)
        if active != initial_active:
            _fail("REVIEWER_UPGRADE_STATE_CHANGED")
        current_transaction, current_plan_document, current_plan, progress = (
            _load_transaction(upgrades, active)
        )
        if (
            current_transaction != transaction
            or current_plan_document != plan_document
            or current_plan != plan
            or progress != initial_progress
        ):
            _fail("REVIEWER_UPGRADE_STATE_CHANGED")
        desired, manifest, source_compose, activation = (
            _load_source_transition_state(plan)
        )
        if progress["phase"] in {PREPARED, QUIESCING}:
            progress, gate = _drive_processing_gate(
                transaction,
                plan_document,
                plan,
                progress,
                manifest,
            )
        else:
            gate = _validate_processing_gate(
                progress["details"].get("processing_gate"),
                plan,
                plan_document["plan_digest"],
                manifest=manifest,
                require_live=progress["phase"]
                not in {ACTIVATING, COMPLETE},
            )
        selected_runner = runner or reconciler._runner_for_manifest(manifest)
        if progress["phase"] in {
            PROMOTING,
            SCHEDULED_MAINTENANCE,
            ACTIVATING,
            COMPLETE,
        }:
            progress = _drive_finalization(
                transaction,
                plan_document,
                plan,
                progress,
                gate,
                selected_runner,
                lock_holder,
            )
            _clear_active(upgrades, active)
            return {
                "code": "REVIEWER_UPGRADE_COMPLETE",
                "operation_id": plan["operation_id"],
                "phase": progress["phase"],
                "status": "complete",
            }
        if progress["phase"] in {QUIESCING, MAINTENANCE}:
            progress, desired, manifest, source_compose = _drive_maintenance(
                transaction,
                plan_document,
                plan,
                progress,
                desired,
                manifest,
                source_compose,
                activation,
                selected_runner,
                lock_holder["descriptor"],
            )
        if progress["phase"] in {BACKING_UP, BACKUP_READY}:
            desired, manifest, source_compose = _validate_source_state(
                plan,
                require_maintenance=True,
            )
        if progress["phase"] in {MAINTENANCE, BACKING_UP, BACKUP_READY} and (
            backup_runner is None and _defer_backup_for_test
        ):
            return {
                "code": "REVIEWER_UPGRADE_WAITING_BACKUP",
                "operation_id": plan["operation_id"],
                "phase": progress["phase"],
                "status": "waiting_backup",
            }
        if progress["phase"] in {MAINTENANCE, BACKING_UP, BACKUP_READY}:
            if backup_runner is None:
                bindings = _live_backup_bindings(
                    plan_document,
                    plan,
                    manifest,
                    source_compose,
                )
                try:
                    backup_runner = backup_docker.create_docker_backup_runner(
                        transaction,
                        bindings,
                        manifest,
                        source_compose,
                        selected_runner,
                    )
                except backup_docker.DockerBackupError as error:
                    raise UpgradeError(
                        "REVIEWER_UPGRADE_BACKUP_INVALID"
                    ) from error
            progress = _drive_backup(
                transaction,
                plan_document,
                plan,
                progress,
                desired,
                manifest,
                source_compose,
                selected_runner,
                backup_runner,
            )
        if progress["phase"] in PRE_REPLACEMENT_PHASES:
            return {
                "code": "REVIEWER_UPGRADE_WAITING_PRE_REPLACEMENT",
                "operation_id": plan["operation_id"],
                "phase": progress["phase"],
                "status": "waiting_pre_replacement",
            }
        desired, manifest, source_compose = _validate_source_state(
            plan,
            require_maintenance=True,
        )
        gate = _validate_processing_gate(
            progress["details"].get("processing_gate"),
            plan,
            plan_document["plan_digest"],
            manifest=manifest,
            require_live=True,
        )
        candidate_path, _candidate_payload, candidate_document = _candidate_compose(
            transaction,
            plan,
        )
        source_document = reconciler._parse_json(
            reconciler._read_private(
                source_compose,
                mode=0o400,
                code="REVIEWER_UPGRADE_STATE_INVALID",
            ),
            "REVIEWER_UPGRADE_STATE_INVALID",
        )
        (
            _source_ref,
            candidate_ref,
            source_repository,
            candidate_repository,
        ) = _candidate_relocation(
            source_document,
            candidate_document,
        )
        if (
            candidate_ref != plan["candidate_image_ref"]
            or str(source_repository) != plan["source_repository_root"]
            or str(candidate_repository) != plan["candidate_repository_root"]
        ):
            _fail()
        _validate_maintenance_runtime(
            manifest,
            source_compose,
            selected_runner,
            gate,
            plan,
            plan_document["plan_digest"],
        )
        if _image_id(manifest, selected_runner, candidate_ref) != plan[
            "candidate_image_id"
        ]:
            _fail("REVIEWER_UPGRADE_CANDIDATE_REBOUND")

        state = _classify_deployment(
            manifest,
            candidate_path,
            candidate_document,
            plan,
            selected_runner,
        )
        if progress["phase"] in {BACKUP_READY, REPLACING}:
            progress, state = _replace_reviewer(
                transaction,
                plan_document,
                plan,
                progress,
                manifest,
                candidate_path,
                candidate_document,
                selected_runner,
            )
        if progress["phase"] in {REVIEWER_READY, SEALING}:
            expected = (
                progress["details"]
                if progress["phase"] == REVIEWER_READY
                else {
                    "candidate_container_id": progress["details"][
                        "candidate_container_id"
                    ],
                    "candidate_image_id": plan["candidate_image_id"],
                    "deployment_digest": progress["details"]["deployment_digest"],
                    "processing_gate": gate,
                }
            )
            ready = _require_ready_state(state, plan, gate, expected)
            if _image_id(manifest, selected_runner, candidate_ref) != plan[
                "candidate_image_id"
            ]:
                _fail("REVIEWER_UPGRADE_CANDIDATE_REBOUND")
            reconciler._smoke(manifest, public=False)
            progress = _seal_candidate(
                transaction,
                plan_document,
                plan,
                progress,
                manifest,
                candidate_path,
                ready,
                selected_runner,
                lock_holder["descriptor"],
                gate["inhibitor"],
            )
        if progress["phase"] == SEALED_MAINTENANCE:
            expected = {
                "candidate_container_id": progress["details"][
                    "candidate_container_id"
                ],
                "candidate_image_id": plan["candidate_image_id"],
                "deployment_digest": progress["details"]["deployment_digest"],
                "processing_gate": gate,
            }
            ready = _require_ready_state(state, plan, gate, expected)
            attempts, quarantined, active_attempt = _validate_attempts(
                progress["details"],
                transaction,
            )
            if active_attempt is None or active_attempt in quarantined:
                _fail("REVIEWER_UPGRADE_SEALED_STATE_INVALID")
            sealed_state = Path(plan["sealed_state_directory"])
            _safe_attempt_directory(sealed_state, transaction)
            if not _sealed_state_valid(
                sealed_state,
                attempts[active_attempt - 1],
                plan,
                manifest,
                ready,
                selected_runner,
            ):
                _fail("REVIEWER_UPGRADE_SEALED_STATE_INVALID")
            reconciler._smoke(manifest, public=False)
        if progress["phase"] != SEALED_MAINTENANCE:
            _fail()
        if _defer_finalization_for_test:
            return {
                "code": "REVIEWER_UPGRADE_SEALED_MAINTENANCE",
                "operation_id": plan["operation_id"],
                "phase": progress["phase"],
                "status": "sealed_maintenance",
            }
        progress = _drive_finalization(
            transaction,
            plan_document,
            plan,
            progress,
            gate,
            selected_runner,
            lock_holder,
        )
        _clear_active(upgrades, active)
        return {
            "code": "REVIEWER_UPGRADE_COMPLETE",
            "operation_id": plan["operation_id"],
            "phase": progress["phase"],
            "status": "complete",
        }


def resume(
    state_parent: Path,
    *,
    unit_directory: Path | None = None,
    lock_file: Path | None = None,
    operation_directory: Path | None = None,
    serial_lock_file: Path | None = None,
    runner: Runner | None = None,
    backup_runner: BackupRunner | None = None,
    lock_descriptor: int | None = None,
    _defer_backup_for_test: bool = False,
    _defer_finalization_for_test: bool = False,
    _skip_processing_lock_binding_for_test: bool = False,
) -> dict[str, Any]:
    """Resume one active transaction under the durable serial lock."""

    parent = reconciler._safe_directory(
        _canonical_path(state_parent, "REVIEWER_UPGRADE_INPUT_INVALID")
    )
    with _upgrade_serialization_lock(
        parent,
        serial_lock_file,
    ) as (_descriptor, binding, _path):
        return _resume_serialized(
            parent,
            unit_directory=unit_directory,
            lock_file=lock_file,
            operation_directory=operation_directory,
            runner=runner,
            backup_runner=backup_runner,
            lock_descriptor=lock_descriptor,
            _defer_backup_for_test=_defer_backup_for_test,
            _defer_finalization_for_test=_defer_finalization_for_test,
            _skip_processing_lock_binding_for_test=(
                _skip_processing_lock_binding_for_test
            ),
            _serial_binding=binding,
        )


def status(state_parent: Path) -> dict[str, Any]:
    """Return a strict, read-only summary of the active transaction."""

    upgrades = _existing_upgrades_directory(state_parent)
    if upgrades is None:
        return {"code": "REVIEWER_UPGRADE_IDLE", "status": "idle"}
    active = _load_active(upgrades, optional=True)
    if active is None:
        return {"code": "REVIEWER_UPGRADE_IDLE", "status": "idle"}
    transaction, _plan_document, plan, progress = _load_transaction(
        upgrades,
        active,
    )
    _candidate_compose(transaction, plan)
    _load_source_transition_state(plan)
    return {
        "code": "REVIEWER_UPGRADE_STATUS",
        "operation_id": plan["operation_id"],
        "phase": progress["phase"],
        "sequence": progress["sequence"],
        "status": (
            "sealed_maintenance"
            if progress["phase"] == SEALED_MAINTENANCE
            else progress["phase"]
        ),
    }


def prepare_lock(
    serial_lock_file: Path,
    lock_file: Path,
    project: str,
) -> dict[str, str]:
    """Create both stable lock inodes before any transaction is published."""

    expected = reconciler._lock_path(project)
    serial_parent = serial_lock_file.parent
    if (
        reconciler.PROJECT.fullmatch(project) is None
        or not serial_lock_file.is_absolute()
        or serial_lock_file.name != SERIAL_LOCK_FILE
        or serial_lock_file != serial_parent / SERIAL_LOCK_FILE
        or _canonical_path(
            serial_parent,
            "REVIEWER_UPGRADE_INPUT_INVALID",
        )
        != serial_parent
        or not lock_file.is_absolute()
        or lock_file != expected
    ):
        _fail("REVIEWER_UPGRADE_INPUT_INVALID")
    try:
        serial_descriptor, created = _prepare_serial_lock_file(serial_lock_file)
    except (OSError, reconciler.ReconcileError) as error:
        raise UpgradeError("REVIEWER_UPGRADE_SERIAL_LOCK_INVALID") from error
    try:
        if created:
            reconciler._fsync_directory(serial_parent)
        descriptor = reconciler._open_host_lock(expected, create=True)
        reconciler._release_lock(descriptor)
    finally:
        os.close(serial_descriptor)
    return {"code": "REVIEWER_UPGRADE_LOCK_PREPARED", "status": "prepared"}


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_command = commands.add_parser("prepare")
    prepare_command.add_argument("--state-directory", required=True, type=Path)
    prepare_command.add_argument("--candidate-compose", required=True, type=Path)
    prepare_command.add_argument("--unit-directory", required=True, type=Path)
    prepare_command.add_argument("--lock-file", required=True, type=Path)
    prepare_command.add_argument("--operation-directory", required=True, type=Path)
    prepare_command.add_argument("--serial-lock-file", required=True, type=Path)
    prepare_command.add_argument("--operation-id")
    prepare_command.add_argument("--lock-fd", type=int)
    resume_command = commands.add_parser("resume")
    resume_command.add_argument("--state-parent", required=True, type=Path)
    resume_command.add_argument("--unit-directory", required=True, type=Path)
    resume_command.add_argument("--lock-file", required=True, type=Path)
    resume_command.add_argument("--operation-directory", required=True, type=Path)
    resume_command.add_argument("--serial-lock-file", required=True, type=Path)
    resume_command.add_argument("--lock-fd", type=int)
    status_command = commands.add_parser("status")
    status_command.add_argument("--state-parent", required=True, type=Path)
    lock_command = commands.add_parser("prepare-lock")
    lock_command.add_argument("--serial-lock-file", required=True, type=Path)
    lock_command.add_argument("--lock-file", required=True, type=Path)
    lock_command.add_argument("--project", required=True)
    return parser


def _failure_exit_status(code: str) -> int:
    if code in RETRYABLE_FAILURE_CODES:
        return 1
    # Unknown codes stop the hot-restart loop.  New public errors must be
    # deliberately classified rather than inheriting behavior by substring.
    return 78


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o077)
    try:
        args = _parser().parse_args(argv)
        if args.command == "prepare":
            result = prepare(
                args.state_directory,
                args.candidate_compose,
                unit_directory=args.unit_directory,
                lock_file=args.lock_file,
                operation_directory=args.operation_directory,
                serial_lock_file=args.serial_lock_file,
                lock_descriptor=args.lock_fd,
                operation_id=args.operation_id,
            )
        elif args.command == "resume":
            result = resume(
                args.state_parent,
                unit_directory=args.unit_directory,
                lock_file=args.lock_file,
                operation_directory=args.operation_directory,
                serial_lock_file=args.serial_lock_file,
                lock_descriptor=args.lock_fd,
            )
        elif args.command == "status":
            result = status(args.state_parent)
        else:
            result = prepare_lock(
                args.serial_lock_file,
                args.lock_file,
                args.project,
            )
        sys.stdout.buffer.write(journal.canonical_json(result) + b"\n")
        return 0
    except UpgradeError as error:
        code = error.code
    except journal.JournalError:
        code = "REVIEWER_UPGRADE_STATE_INVALID"
    except reconciler.ReconcileError as error:
        code = error.code
    except (OSError, ValueError, TypeError):
        code = "REVIEWER_UPGRADE_FAILED"
    sys.stderr.buffer.write(
        journal.canonical_json({"code": code, "status": "failed"}) + b"\n"
    )
    return _failure_exit_status(code)


if __name__ == "__main__":
    raise SystemExit(main())
