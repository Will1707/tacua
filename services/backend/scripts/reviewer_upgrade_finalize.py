#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Transaction-independent, crash-resumable reviewer-upgrade finalization.

The caller journals phase transitions.  This module accepts only exact sealed
state, unit, processing-gate, and lock-owner bindings, and exposes idempotent
operations that can be retried after any unrecorded process or host crash.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any, Callable, Mapping, NoReturn


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import reconcile_compose_deployment as reconciler  # noqa: E402
import reviewer_upgrade_manager as manager  # noqa: E402
import reviewer_upgrade_systemd as upgrade_systemd  # noqa: E402


RECEIPT_CONTRACT = "tacua.reviewer-upgrade-finalize-receipt@1.0.0"
INHIBITOR_CONTRACT = "tacua.reviewer-upgrade-inhibitor@1.0.0"


class FinalizeError(RuntimeError):
    """Stable, content-free finalization failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str = "UPGRADE_FINALIZE_STATE_INVALID") -> NoReturn:
    raise FinalizeError(code)


@dataclass(frozen=True)
class UpgradeInhibitor:
    contract_version: str
    inhibitor_digest: str
    plan_digest: str
    project: str

    def document(self) -> dict[str, str]:
        document = {
            "contract_version": self.contract_version,
            "inhibitor_digest": self.inhibitor_digest,
            "plan_digest": self.plan_digest,
            "project": self.project,
        }
        try:
            validated = reconciler._validate_upgrade_inhibitor(
                document,
                project=self.project,
            )
        except reconciler.ReconcileError as error:
            raise FinalizeError("UPGRADE_FINALIZE_GATE_INVALID") from error
        if (
            self.contract_version != INHIBITOR_CONTRACT
            or validated != document
            or reconciler._canonical(document)
            != reconciler._canonical(validated)
        ):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        return document


@dataclass(frozen=True)
class DirectoryIdentity:
    device: int
    gid: int
    inode: int
    mode: int
    uid: int

    def validated(self) -> DirectoryIdentity:
        values = (self.device, self.gid, self.inode, self.mode, self.uid)
        if (
            any(type(value) is not int for value in values)
            or self.device < 0
            or self.gid < 0
            or self.inode <= 0
            or self.mode != 0o700
            or self.uid != os.geteuid()
        ):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        return self


@dataclass(frozen=True)
class ProcessingGateBinding:
    operation_directory: Path
    directory_identity: DirectoryIdentity
    inhibitor: UpgradeInhibitor

    def validated(self) -> ProcessingGateBinding:
        if (
            not isinstance(self.operation_directory, Path)
            or not self.operation_directory.is_absolute()
            or str(self.operation_directory).startswith("//")
            or any(part in {".", ".."} for part in self.operation_directory.parts)
            or not isinstance(self.directory_identity, DirectoryIdentity)
            or not isinstance(self.inhibitor, UpgradeInhibitor)
        ):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        self.directory_identity.validated()
        document = self.inhibitor.document()
        if self.operation_directory.name != (
            f"tacua-compose-processing-{document['project']}"
        ):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        return self


@dataclass(frozen=True)
class CallerOwnedProcessingLock:
    """Callbacks over the resumer's mutable descriptor holder.

    ``current_descriptor`` must return the holder's currently owned descriptor.
    ``handoff`` must implement the strict release/close, action, and
    finally-reacquire/replace contract from ``reviewer_upgrade_manager``.
    """

    current_descriptor: Callable[[], int]
    handoff: manager.ProcessingLockHandoff

    def validated(self) -> CallerOwnedProcessingLock:
        if not callable(self.current_descriptor) or not callable(self.handoff):
            _fail("UPGRADE_FINALIZE_LOCK_INVALID")
        return self


@dataclass(frozen=True)
class FinalizeBindings:
    target_state_directory: Path
    unit_directory: Path
    old_units: upgrade_systemd.UnitBundle
    target_units: upgrade_systemd.UnitBundle
    manager_binaries: manager.ManagerBinaries
    loaded_target: Mapping[str, manager.LoadedUnitExpectation]
    timer_enable_link_paths: tuple[Path, ...]
    processing_gate: ProcessingGateBinding
    processing_lock: CallerOwnedProcessingLock


def _canonical_existing_directory(path: Path, code: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail(code)
    try:
        return reconciler._safe_directory(path)
    except reconciler.ReconcileError as error:
        raise FinalizeError(code) from error


def _canonical_unit_directory(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail("UPGRADE_FINALIZE_UNIT_INVALID")
    descriptor: int | None = None
    try:
        descriptor, _binding = upgrade_systemd._validated_unit_directory(
            path,
            expected_uid=os.geteuid(),
        )
    except upgrade_systemd.UnitContractError as error:
        raise FinalizeError("UPGRADE_FINALIZE_UNIT_INVALID") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return path


def _validated_bindings(bindings: FinalizeBindings) -> FinalizeBindings:
    if not isinstance(bindings, FinalizeBindings):
        _fail("UPGRADE_FINALIZE_INPUT_INVALID")
    state = _canonical_existing_directory(
        bindings.target_state_directory,
        "UPGRADE_FINALIZE_STATE_INVALID",
    )
    unit_directory = _canonical_unit_directory(bindings.unit_directory)
    if (
        not isinstance(bindings.old_units, upgrade_systemd.UnitBundle)
        or not isinstance(bindings.target_units, upgrade_systemd.UnitBundle)
        or not isinstance(bindings.manager_binaries, manager.ManagerBinaries)
        or not isinstance(bindings.loaded_target, Mapping)
        or set(bindings.loaded_target) != set(manager.UNIT_NAMES)
        or not isinstance(bindings.timer_enable_link_paths, tuple)
        or not bindings.timer_enable_link_paths
        or not isinstance(bindings.processing_gate, ProcessingGateBinding)
        or not isinstance(bindings.processing_lock, CallerOwnedProcessingLock)
    ):
        _fail("UPGRADE_FINALIZE_INPUT_INVALID")
    try:
        bindings.manager_binaries.validated()
        upgrade_systemd.UnitBundle(tuple(bindings.old_units.units))
        upgrade_systemd.UnitBundle(tuple(bindings.target_units.units))
    except (manager.ManagerError, upgrade_systemd.UnitContractError) as error:
        raise FinalizeError("UPGRADE_FINALIZE_INPUT_INVALID") from error
    loaded: dict[str, manager.LoadedUnitExpectation] = {}
    for name in manager.UNIT_NAMES:
        expectation = bindings.loaded_target[name]
        if not isinstance(expectation, manager.LoadedUnitExpectation):
            _fail("UPGRADE_FINALIZE_INPUT_INVALID")
        try:
            expectation.validated(name)
        except manager.ManagerError as error:
            raise FinalizeError("UPGRADE_FINALIZE_INPUT_INVALID") from error
        if expectation.fragment_path != unit_directory / name:
            _fail("UPGRADE_FINALIZE_INPUT_INVALID")
        loaded[name] = expectation
    links = tuple(bindings.timer_enable_link_paths)
    try:
        manager._validated_enable_links(
            tuple(
                manager.EnableLinkExpectation(
                    path,
                    unit_directory / manager.RECONCILE_TIMER,
                )
                for path in links
            )
        )
    except manager.ManagerError as error:
        raise FinalizeError("UPGRADE_FINALIZE_INPUT_INVALID") from error
    gate = bindings.processing_gate.validated()
    locks = bindings.processing_lock.validated()
    return FinalizeBindings(
        target_state_directory=state,
        unit_directory=unit_directory,
        old_units=bindings.old_units,
        target_units=bindings.target_units,
        manager_binaries=bindings.manager_binaries,
        loaded_target=loaded,
        timer_enable_link_paths=links,
        processing_gate=gate,
        processing_lock=locks,
    )


def _timer_enable_links(
    bindings: FinalizeBindings,
) -> tuple[manager.EnableLinkExpectation, ...]:
    return tuple(
        manager.EnableLinkExpectation(
            path,
            bindings.unit_directory / manager.RECONCILE_TIMER,
        )
        for path in bindings.timer_enable_link_paths
    )


def _load_target(
    bindings: FinalizeBindings,
) -> tuple[dict[str, Any], dict[str, Any], Path]:
    try:
        desired, manifest, compose = reconciler._load_bound_state(
            bindings.target_state_directory
        )
    except reconciler.ReconcileError as error:
        raise FinalizeError("UPGRADE_FINALIZE_STATE_INVALID") from error
    gate = bindings.processing_gate
    inhibitor = gate.inhibitor.document()
    expected_operation = (
        Path(manifest["operation_directory"])
        / f"tacua-compose-processing-{manifest['project']}"
    )
    if (
        manifest.get("project") != inhibitor["project"]
        or gate.operation_directory != expected_operation
    ):
        _fail("UPGRADE_FINALIZE_GATE_INVALID")
    return desired, manifest, compose


def _load_activation(
    bindings: FinalizeBindings,
    desired: Mapping[str, Any],
    *,
    code: str = "UPGRADE_FINALIZE_STATE_INVALID",
) -> dict[str, Any] | None:
    """Keep reconciler state failures inside the finalizer error contract."""

    try:
        return reconciler._load_activation(
            bindings.target_state_directory,
            desired,
        )
    except reconciler.ReconcileError as error:
        raise FinalizeError(code) from error


def _directory_matches(
    metadata: os.stat_result,
    identity: DirectoryIdentity,
) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == identity.uid
        and metadata.st_gid == identity.gid
        and metadata.st_dev == identity.device
        and metadata.st_ino == identity.inode
        and stat.S_IMODE(metadata.st_mode) == identity.mode
    )


def _same_directory_binding(
    observed: os.stat_result,
    expected: os.stat_result,
) -> bool:
    return (
        stat.S_ISDIR(observed.st_mode)
        and not stat.S_ISLNK(observed.st_mode)
        and (observed.st_dev, observed.st_ino)
        == (expected.st_dev, expected.st_ino)
        and observed.st_uid == expected.st_uid
        and observed.st_gid == expected.st_gid
        and stat.S_IMODE(observed.st_mode) == stat.S_IMODE(expected.st_mode)
    )


def _gate_entries(bindings: FinalizeBindings) -> set[str]:
    gate = bindings.processing_gate
    try:
        if gate.operation_directory.resolve(strict=True) != gate.operation_directory:
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        metadata = gate.operation_directory.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not _directory_matches(
            metadata,
            gate.directory_identity,
        ):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        entries = {entry.name for entry in gate.operation_directory.iterdir()}
    except FinalizeError:
        raise
    except OSError as error:
        raise FinalizeError("UPGRADE_FINALIZE_GATE_INVALID") from error
    return entries


def _require_live_gate(bindings: FinalizeBindings, manifest: Mapping[str, Any]) -> None:
    if _gate_entries(bindings) != {reconciler.UPGRADE_INHIBITOR_FILE}:
        _fail("UPGRADE_FINALIZE_GATE_INVALID")
    try:
        reconciler._require_upgrade_inhibitor(
            manifest,
            bindings.processing_gate.inhibitor.document(),
        )
    except reconciler.ReconcileError as error:
        raise FinalizeError("UPGRADE_FINALIZE_GATE_INVALID") from error


def _current_descriptor(bindings: FinalizeBindings) -> int:
    try:
        descriptor = bindings.processing_lock.current_descriptor()
    except Exception as error:
        raise FinalizeError("UPGRADE_FINALIZE_LOCK_INVALID") from error
    if type(descriptor) is not int or descriptor < 0:
        _fail("UPGRADE_FINALIZE_LOCK_INVALID")
    try:
        reconciler._adopt_host_lock(
            bindings.processing_gate.inhibitor.project,
            descriptor,
        )
    except reconciler.ReconcileError as error:
        if error.code == "RECONCILE_DEFERRED":
            raise FinalizeError("UPGRADE_FINALIZE_LOCK_CONTENDED") from error
        raise FinalizeError("UPGRADE_FINALIZE_LOCK_INVALID") from error
    return descriptor


def _validate_replacement_descriptor(
    bindings: FinalizeBindings,
    descriptor: int,
) -> int:
    if _current_descriptor(bindings) != descriptor:
        _fail("UPGRADE_FINALIZE_LOCK_INVALID")
    return descriptor


def _receipt(
    operation: str,
    status: str,
    desired: Mapping[str, Any],
    details: Mapping[str, Any],
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "contract_version": RECEIPT_CONTRACT,
        "details": dict(details),
        "generation": desired["generation"],
        "operation": operation,
        "project": desired["project"],
        "receipt_digest": "",
        "status": status,
    }
    try:
        receipt["receipt_digest"] = reconciler._document_digest(
            receipt,
            "receipt_digest",
        )
        if reconciler._parse_json(
            reconciler._canonical(receipt),
            "UPGRADE_FINALIZE_RECEIPT_INVALID",
        ) != receipt:
            _fail("UPGRADE_FINALIZE_RECEIPT_INVALID")
    except FinalizeError:
        raise
    except (reconciler.ReconcileError, TypeError, ValueError) as error:
        raise FinalizeError("UPGRADE_FINALIZE_RECEIPT_INVALID") from error
    return receipt


def promote_target_maintenance(
    bindings: FinalizeBindings,
    runner: manager.Runner,
    *,
    timer_deadline_seconds: float = 15.0,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[int, dict[str, Any]]:
    """Converge target units and prove manual maintenance reconciliation."""

    bindings = _validated_bindings(bindings)
    desired, manifest, _compose = _load_target(bindings)
    if (
        desired["desired"] != "maintenance"
        or _load_activation(bindings, desired) is not None
    ):
        _fail("UPGRADE_FINALIZE_STATE_INVALID")
    _require_live_gate(bindings, manifest)
    _current_descriptor(bindings)
    try:
        manager.stop_disable_verify_timer(
            bindings.manager_binaries,
            runner,
            enable_links=_timer_enable_links(bindings),
        )
        classified = upgrade_systemd.classify_installed_units(
            bindings.unit_directory,
            bindings.old_units,
            bindings.target_units,
        )
        if any(
            item.state is upgrade_systemd.InstalledUnitState.UNKNOWN
            for item in classified
        ):
            _fail("UPGRADE_FINALIZE_UNIT_UNKNOWN")
        converged = upgrade_systemd.converge_installed_units(
            bindings.unit_directory,
            bindings.old_units,
            bindings.target_units,
        )
        if any(
            item.state is not upgrade_systemd.InstalledUnitState.TARGET
            for item in converged
        ):
            _fail("UPGRADE_FINALIZE_UNIT_INVALID")
        unit_paths = {
            name: bindings.unit_directory / name for name in manager.UNIT_NAMES
        }
        manager.verify_unit_syntax(
            bindings.manager_binaries,
            runner,
            unit_paths,
        )
        manager.daemon_reload(bindings.manager_binaries, runner)
        manager.verify_loaded_units(
            bindings.manager_binaries,
            runner,
            bindings.loaded_target,
        )
        descriptor = manager.restart_reconcile_lock(
            bindings.manager_binaries,
            runner,
            with_released_processing_lock=bindings.processing_lock.handoff,
        )
        _validate_replacement_descriptor(bindings, descriptor)

        def verify_maintenance() -> bool:
            current, current_manifest, _current_compose = _load_target(bindings)
            return (
                current["desired"] == "maintenance"
                and current_manifest == manifest
                and _load_activation(bindings, current) is None
            )

        descriptor = manager.start_verify_maintenance_reconcile(
            bindings.manager_binaries,
            runner,
            with_released_processing_lock=bindings.processing_lock.handoff,
            verify_maintenance=verify_maintenance,
        )
        _validate_replacement_descriptor(bindings, descriptor)
        _require_live_gate(bindings, manifest)
        manager.enable_restart_timer(
            bindings.manager_binaries,
            runner,
            enable_links=_timer_enable_links(bindings),
        )
        manager.prove_timer_enabled_active_waiting(
            bindings.manager_binaries,
            runner,
            enable_links=_timer_enable_links(bindings),
            deadline_seconds=timer_deadline_seconds,
            monotonic=monotonic,
            sleep=sleep,
        )
    except FinalizeError:
        raise
    except manager.ManagerError as error:
        if error.code == "UPGRADE_MANAGER_LOCK_CONTENDED":
            raise FinalizeError("UPGRADE_FINALIZE_LOCK_CONTENDED") from error
        if error.code in {
            "UPGRADE_MANAGER_LOCK_HANDOFF_FAILED",
            "UPGRADE_MANAGER_LOCK_HANDOFF_INVALID",
        }:
            raise FinalizeError("UPGRADE_FINALIZE_LOCK_INVALID") from error
        if error.code == "UPGRADE_MANAGER_TIMER_LINK_INVALID":
            raise FinalizeError(
                "UPGRADE_FINALIZE_TIMER_LINK_INVALID"
            ) from error
        if error.code in {
            "UPGRADE_MANAGER_EXPECTATION_INVALID",
            "UPGRADE_MANAGER_INPUT_INVALID",
            "UPGRADE_MANAGER_LOADED_UNIT_INVALID",
            "UPGRADE_MANAGER_UNIT_VERIFY_FAILED",
        }:
            raise FinalizeError("UPGRADE_FINALIZE_UNIT_INVALID") from error
        raise FinalizeError("UPGRADE_FINALIZE_MANAGER_FAILED") from error
    except upgrade_systemd.UnitContractError as error:
        raise FinalizeError("UPGRADE_FINALIZE_UNIT_INVALID") from error
    current, current_manifest, _compose = _load_target(bindings)
    if current != desired or current_manifest != manifest:
        _fail("UPGRADE_FINALIZE_STATE_INVALID")
    _require_live_gate(bindings, manifest)
    receipt = _receipt(
        "promote_target_maintenance",
        "maintenance_ready",
        current,
        {"target_unit_digests": bindings.target_units.digests()},
    )
    return descriptor, receipt


def activate_target(
    bindings: FinalizeBindings,
    runner: manager.Runner,
) -> tuple[int, dict[str, Any]]:
    """Activate or resume activation while the exact inhibitor remains live."""

    bindings = _validated_bindings(bindings)
    desired, manifest, _compose = _load_target(bindings)
    if desired["desired"] not in {"maintenance", "running"}:
        _fail("UPGRADE_FINALIZE_STATE_INVALID")
    _require_live_gate(bindings, manifest)
    descriptor = _current_descriptor(bindings)
    try:
        result = reconciler.set_running(
            bindings.target_state_directory,
            runner=runner,
            lock_descriptor=descriptor,
            upgrade_inhibitor=bindings.processing_gate.inhibitor.document(),
        )
    except reconciler.ReconcileError as error:
        if error.code == "RECONCILE_DEFERRED":
            raise FinalizeError("UPGRADE_FINALIZE_LOCK_CONTENDED") from error
        raise FinalizeError("UPGRADE_FINALIZE_ACTIVATION_FAILED") from error
    if result != {"code": "RECONCILE_RECOVERED", "status": "recovered"}:
        _fail("UPGRADE_FINALIZE_ACTIVATION_FAILED")
    current, current_manifest, _compose = _load_target(bindings)
    if (
        current["desired"] != "running"
        or current_manifest != manifest
        or _load_activation(
            bindings,
            current,
            code="UPGRADE_FINALIZE_ACTIVATION_FAILED",
        )
        is not None
    ):
        _fail("UPGRADE_FINALIZE_ACTIVATION_FAILED")
    _require_live_gate(bindings, manifest)
    receipt = _receipt(
        "activate_target",
        "running_gate_held",
        current,
        {"inhibitor_digest": bindings.processing_gate.inhibitor.inhibitor_digest},
    )
    return descriptor, receipt


def _same_marker_metadata(
    observed: os.stat_result,
    expected: os.stat_result,
) -> bool:
    return all(
        getattr(observed, field) == getattr(expected, field)
        for field in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def _read_exact_marker(
    descriptor: int,
    expected: bytes,
    directory_identity: DirectoryIdentity,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os,
        "O_NOFOLLOW",
        0,
    )
    marker_descriptor: int | None = None
    try:
        if not _directory_matches(os.fstat(descriptor), directory_identity):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        metadata = os.stat(
            reconciler.UPGRADE_INHIBITOR_FILE,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(expected)
        ):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        marker_descriptor = os.open(
            reconciler.UPGRADE_INHIBITOR_FILE,
            flags,
            dir_fd=descriptor,
        )
        opened = os.fstat(marker_descriptor)
        if not _same_marker_metadata(opened, metadata):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        chunks: list[bytes] = []
        size = 0
        while size <= len(expected):
            chunk = os.read(marker_descriptor, len(expected) + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(marker_descriptor)
        current = os.stat(
            reconciler.UPGRADE_INHIBITOR_FILE,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
        if (
            payload != expected
            or not _same_marker_metadata(after, metadata)
            or not _same_marker_metadata(current, metadata)
            or not _directory_matches(os.fstat(descriptor), directory_identity)
        ):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
    except FinalizeError:
        raise
    except OSError as error:
        raise FinalizeError("UPGRADE_FINALIZE_GATE_INVALID") from error
    finally:
        if marker_descriptor is not None:
            os.close(marker_descriptor)


def _require_gate_absent(bindings: FinalizeBindings) -> None:
    path = bindings.processing_gate.operation_directory
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise FinalizeError("UPGRADE_FINALIZE_GATE_INVALID") from error
    _fail("UPGRADE_FINALIZE_GATE_INVALID")


def remove_processing_gate(
    bindings: FinalizeBindings,
) -> tuple[int, dict[str, Any]]:
    """Durably remove only the exact bound gate after settled activation."""

    bindings = _validated_bindings(bindings)
    desired, _manifest, _compose = _load_target(bindings)
    if (
        desired["desired"] != "running"
        or _load_activation(bindings, desired) is not None
    ):
        _fail("UPGRADE_FINALIZE_STATE_INVALID")
    descriptor = _current_descriptor(bindings)
    operation = bindings.processing_gate.operation_directory
    parent = _canonical_existing_directory(
        operation.parent,
        "UPGRADE_FINALIZE_GATE_INVALID",
    )
    try:
        parent_metadata = parent.lstat()
    except OSError as error:
        raise FinalizeError("UPGRADE_FINALIZE_GATE_INVALID") from error
    try:
        operation_metadata = operation.lstat()
    except FileNotFoundError:
        operation_metadata = None
    except OSError as error:
        raise FinalizeError("UPGRADE_FINALIZE_GATE_INVALID") from error
    if operation_metadata is not None:
        if stat.S_ISLNK(operation_metadata.st_mode) or not _directory_matches(
            operation_metadata,
            bindings.processing_gate.directory_identity,
        ):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        parent_descriptor: int | None = None
        operation_descriptor: int | None = None
        try:
            parent_descriptor = os.open(
                parent,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            if (
                not _same_directory_binding(
                    os.fstat(parent_descriptor),
                    parent_metadata,
                )
                or not _same_directory_binding(
                    parent.lstat(),
                    parent_metadata,
                )
            ):
                _fail("UPGRADE_FINALIZE_GATE_INVALID")
            operation_descriptor = os.open(
                operation.name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            opened = os.fstat(operation_descriptor)
            if not _directory_matches(
                opened,
                bindings.processing_gate.directory_identity,
            ):
                _fail("UPGRADE_FINALIZE_GATE_INVALID")
            bound_path = os.stat(
                operation.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if not _directory_matches(
                bound_path,
                bindings.processing_gate.directory_identity,
            ):
                _fail("UPGRADE_FINALIZE_GATE_INVALID")
            entries = set(os.listdir(operation_descriptor))
            if entries == {reconciler.UPGRADE_INHIBITOR_FILE}:
                expected = reconciler._canonical(
                    bindings.processing_gate.inhibitor.document()
                )
                _read_exact_marker(
                    operation_descriptor,
                    expected,
                    bindings.processing_gate.directory_identity,
                )
                bound_path = os.stat(
                    operation.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if not _directory_matches(
                    bound_path,
                    bindings.processing_gate.directory_identity,
                ):
                    _fail("UPGRADE_FINALIZE_GATE_INVALID")
                os.unlink(
                    reconciler.UPGRADE_INHIBITOR_FILE,
                    dir_fd=operation_descriptor,
                )
                os.fsync(operation_descriptor)
                entries = set(os.listdir(operation_descriptor))
            if entries:
                _fail("UPGRADE_FINALIZE_GATE_INVALID")
            current = operation.lstat()
            if not _directory_matches(
                current,
                bindings.processing_gate.directory_identity,
            ):
                _fail("UPGRADE_FINALIZE_GATE_INVALID")
            if (
                not _same_directory_binding(
                    os.fstat(parent_descriptor),
                    parent_metadata,
                )
                or not _same_directory_binding(
                    parent.lstat(),
                    parent_metadata,
                )
            ):
                _fail("UPGRADE_FINALIZE_GATE_INVALID")
            os.rmdir(operation.name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
            try:
                os.stat(
                    operation.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                _fail("UPGRADE_FINALIZE_GATE_INVALID")
            if (
                not _same_directory_binding(
                    os.fstat(parent_descriptor),
                    parent_metadata,
                )
                or not _same_directory_binding(
                    parent.lstat(),
                    parent_metadata,
                )
            ):
                _fail("UPGRADE_FINALIZE_GATE_INVALID")
        except FinalizeError:
            raise
        except OSError as error:
            raise FinalizeError("UPGRADE_FINALIZE_GATE_INVALID") from error
        finally:
            if operation_descriptor is not None:
                os.close(operation_descriptor)
            if parent_descriptor is not None:
                os.close(parent_descriptor)
    # This proof is intentionally common to both the just-removed and
    # already-absent recovery states.  A crash after rmdir(2) but before the
    # parent fsync must not be allowed to checkpoint gate_absent without first
    # making that prior unlink durable on retry.
    absence_parent_descriptor: int | None = None
    try:
        absence_parent_descriptor = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        if (
            not _same_directory_binding(
                os.fstat(absence_parent_descriptor),
                parent_metadata,
            )
            or not _same_directory_binding(parent.lstat(), parent_metadata)
        ):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        try:
            os.stat(
                operation.name,
                dir_fd=absence_parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        os.fsync(absence_parent_descriptor)
        try:
            os.stat(
                operation.name,
                dir_fd=absence_parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
        if (
            not _same_directory_binding(
                os.fstat(absence_parent_descriptor),
                parent_metadata,
            )
            or not _same_directory_binding(parent.lstat(), parent_metadata)
        ):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
    except FinalizeError:
        raise
    except OSError as error:
        raise FinalizeError("UPGRADE_FINALIZE_GATE_INVALID") from error
    finally:
        if absence_parent_descriptor is not None:
            os.close(absence_parent_descriptor)
    _require_gate_absent(bindings)
    try:
        if not _same_directory_binding(parent.lstat(), parent_metadata):
            _fail("UPGRADE_FINALIZE_GATE_INVALID")
    except FinalizeError:
        raise
    except OSError as error:
        raise FinalizeError("UPGRADE_FINALIZE_GATE_INVALID") from error
    current, _manifest, _compose = _load_target(bindings)
    receipt = _receipt(
        "remove_processing_gate",
        "gate_absent",
        current,
        {"inhibitor_digest": bindings.processing_gate.inhibitor.inhibitor_digest},
    )
    return descriptor, receipt


def prove_later_scheduled_reconcile(
    bindings: FinalizeBindings,
    runner: manager.Runner,
    *,
    deadline_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[int, dict[str, Any]]:
    """Prove one later timer invocation after the processing gate is gone."""

    bindings = _validated_bindings(bindings)
    desired, manifest, _compose = _load_target(bindings)
    if (
        desired["desired"] != "running"
        or _load_activation(bindings, desired) is not None
    ):
        _fail("UPGRADE_FINALIZE_STATE_INVALID")
    _require_gate_absent(bindings)
    _current_descriptor(bindings)
    try:
        descriptor, invocation_id = manager.prove_later_scheduled_reconcile(
            bindings.manager_binaries,
            runner,
            with_released_processing_lock=bindings.processing_lock.handoff,
            enable_links=_timer_enable_links(bindings),
            deadline_seconds=deadline_seconds,
            monotonic=monotonic,
            sleep=sleep,
        )
    except manager.ManagerError as error:
        if error.code == "UPGRADE_MANAGER_LOCK_CONTENDED":
            raise FinalizeError("UPGRADE_FINALIZE_LOCK_CONTENDED") from error
        if error.code in {
            "UPGRADE_MANAGER_LOCK_HANDOFF_FAILED",
            "UPGRADE_MANAGER_LOCK_HANDOFF_INVALID",
        }:
            raise FinalizeError("UPGRADE_FINALIZE_LOCK_INVALID") from error
        if error.code == "UPGRADE_MANAGER_TIMER_LINK_INVALID":
            raise FinalizeError(
                "UPGRADE_FINALIZE_TIMER_LINK_INVALID"
            ) from error
        if error.code in {
            "UPGRADE_MANAGER_EXPECTATION_INVALID",
            "UPGRADE_MANAGER_INPUT_INVALID",
            "UPGRADE_MANAGER_LOADED_UNIT_INVALID",
        }:
            raise FinalizeError("UPGRADE_FINALIZE_UNIT_INVALID") from error
        raise FinalizeError("UPGRADE_FINALIZE_SCHEDULED_FAILED") from error
    _validate_replacement_descriptor(bindings, descriptor)
    current, current_manifest, _compose = _load_target(bindings)
    if (
        current != desired
        or current_manifest != manifest
        or _load_activation(bindings, current) is not None
    ):
        _fail("UPGRADE_FINALIZE_STATE_INVALID")
    _require_gate_absent(bindings)
    receipt = _receipt(
        "prove_later_scheduled_reconcile",
        "scheduled_reconcile_proven",
        current,
        {"invocation_id": invocation_id},
    )
    return descriptor, receipt
