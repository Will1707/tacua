#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retain and terminally abandon one exhausted pre-replacement upgrade.

This is intentionally not a general cancel or rollback command.  It accepts
only an active transaction stopped at ``backing_up`` with exactly three
marker-only failed backup attempts.  It proves that the original deployment
and reconciliation units remain exact, returns that original state to running,
removes only the exact plan-bound processing gate, writes an immutable receipt,
and retires (rather than deletes) the active selector.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import os
from pathlib import Path
import stat
import sys
from typing import Any, Mapping, NoReturn, Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))

import reconcile_compose_deployment as reconciler  # noqa: E402
import reviewer_upgrade_backup as backup  # noqa: E402
import reviewer_upgrade_finalize as finalize  # noqa: E402
import reviewer_upgrade_journal as journal  # noqa: E402
import reviewer_upgrade_transaction as upgrade  # noqa: E402


ABANDONMENT_CONTRACT = "tacua.reviewer-upgrade-abandonment@1.0.0"
ABANDONMENT_RECEIPT_FILE = "abandonment-receipt.json"
ABANDONMENT_RECEIPT_STAGING_FILE = ".abandonment-receipt.json.next"
RETIRED_ACTIVE_FILE = "retired-active.json"
REASON = "backup_attempts_exhausted"

_INVALID = "REVIEWER_UPGRADE_ABANDON_INVALID"
_NOT_EXHAUSTED = "REVIEWER_UPGRADE_ABANDON_NOT_EXHAUSTED"
_RECOVERY_FAILED = "REVIEWER_UPGRADE_ABANDON_RECOVERY_FAILED"
_STATE_CHANGED = "REVIEWER_UPGRADE_ABANDON_STATE_CHANGED"

Runner = upgrade.Runner


class AbandonError(RuntimeError):
    """A stable, content-free abandonment failure."""

    def __init__(self, code: str = _INVALID) -> None:
        super().__init__(code)
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        raise AbandonError(_INVALID)


def _fail(code: str = _INVALID) -> NoReturn:
    raise AbandonError(code)


def _document_digest(value: Mapping[str, Any], field: str) -> str:
    try:
        return reconciler._document_digest(value, field)
    except (TypeError, ValueError, reconciler.ReconcileError) as error:
        raise AbandonError(_INVALID) from error


def _expected_active(operation_id: str, plan_digest: str) -> dict[str, str]:
    value = {
        "active_digest": "",
        "contract_version": upgrade.ACTIVE_CONTRACT,
        "operation_id": operation_id,
        "plan_digest": plan_digest,
    }
    value["active_digest"] = upgrade._active_digest(value)
    try:
        return upgrade._validate_active(value)
    except upgrade.UpgradeError as error:
        raise AbandonError(_INVALID) from error


def _load_operation(
    state_parent: Path,
    operation_id: str,
) -> tuple[
    Path,
    Path,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, str],
]:
    if upgrade.OPERATION_ID.fullmatch(operation_id) is None:
        _fail(_INVALID)
    try:
        upgrades = upgrade._existing_upgrades_directory(state_parent)
        if upgrades is None:
            _fail(_INVALID)
        transaction = upgrade._transaction_directory(upgrades, operation_id)
        plan_document = journal.load_plan(transaction)
        plan = upgrade._validate_plan(plan_document)
        progress = journal.load_progress(transaction, plan_document)
        if progress is None:
            _fail(_INVALID)
        expected_active = _expected_active(
            operation_id,
            plan_document["plan_digest"],
        )
        loaded = upgrade._load_transaction(upgrades, expected_active)
    except AbandonError:
        raise
    except (journal.JournalError, upgrade.UpgradeError) as error:
        raise AbandonError(_INVALID) from error
    if loaded != (transaction, plan_document, plan, progress):
        _fail(_STATE_CHANGED)
    if progress["phase"] != upgrade.BACKING_UP:
        _fail(_NOT_EXHAUSTED)
    return (
        upgrades,
        transaction,
        plan_document,
        plan,
        progress,
        expected_active,
    )


def _read_exact_file(
    path: Path,
    *,
    maximum: int = journal.MAX_DOCUMENT_BYTES,
    links: set[int] = frozenset({1}),
) -> tuple[bytes, os.stat_result]:
    descriptor: int | None = None
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
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
            or not 1 <= before.st_size <= maximum
            or (lexical.st_dev, lexical.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            _fail(_INVALID)
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
        current = path.lstat()
        fields = (
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
        if (
            len(payload) != before.st_size
            or len(payload) > maximum
            or tuple(getattr(before, field) for field in fields)
            != tuple(getattr(after, field) for field in fields)
            or tuple(getattr(after, field) for field in fields)
            != tuple(getattr(current, field) for field in fields)
        ):
            _fail(_INVALID)
        return bytes(payload), after
    except AbandonError:
        raise
    except OSError as error:
        raise AbandonError(_INVALID) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_receipt(value: Any) -> dict[str, Any]:
    keys = {
        "active_selector_digest",
        "backup_evidence",
        "contract_version",
        "operation_id",
        "phase",
        "plan_digest",
        "processing_gate",
        "progress_digest",
        "progress_sequence",
        "reason",
        "receipt_digest",
        "source",
        "status",
        "unit_digests",
    }
    source_keys = {
        "compose_digest",
        "deployment_digest",
        "generation",
        "manifest_digest",
        "state_digest",
    }
    if (
        type(value) is not dict
        or set(value) != keys
        or value.get("contract_version") != ABANDONMENT_CONTRACT
        or value.get("status") != "abandoned"
        or value.get("reason") != REASON
        or value.get("phase") != upgrade.BACKING_UP
        or upgrade.OPERATION_ID.fullmatch(str(value.get("operation_id"))) is None
        or any(
            reconciler.DIGEST.fullmatch(str(value.get(key))) is None
            for key in (
                "active_selector_digest",
                "plan_digest",
                "progress_digest",
                "receipt_digest",
            )
        )
        or type(value.get("progress_sequence")) is not int
        or type(value["progress_sequence"]) is bool
        or value["progress_sequence"] <= 0
        or type(value.get("backup_evidence")) is not dict
        or type(value.get("source")) is not dict
        or set(value["source"]) != source_keys
        or reconciler.GENERATION.fullmatch(
            str(value["source"].get("generation"))
        )
        is None
        or any(
            reconciler.DIGEST.fullmatch(str(value["source"].get(key))) is None
            for key in (
                "compose_digest",
                "deployment_digest",
                "manifest_digest",
                "state_digest",
            )
        )
        or type(value.get("unit_digests")) is not dict
        or set(value["unit_digests"]) != set(upgrade.upgrade_systemd.UNIT_NAMES)
        or any(
            reconciler.DIGEST.fullmatch(str(digest)) is None
            for digest in value["unit_digests"].values()
        )
        or type(value.get("processing_gate")) is not dict
        or set(value["processing_gate"]) != {"inhibitor_digest", "status"}
        or value["processing_gate"].get("status") != "absent"
        or reconciler.DIGEST.fullmatch(
            str(value["processing_gate"].get("inhibitor_digest"))
        )
        is None
        or value.get("receipt_digest")
        != _document_digest(value, "receipt_digest")
    ):
        _fail(_INVALID)
    try:
        evidence = backup.validate_exhausted_backup_evidence_document(
            value["backup_evidence"]
        )
        expected_active = _expected_active(
            value["operation_id"],
            value["plan_digest"],
        )
        if (
            evidence["plan_digest"] != value["plan_digest"]
            or expected_active["active_digest"]
            != value["active_selector_digest"]
        ):
            _fail(_INVALID)
        payload = journal.canonical_json(value)
        if journal.parse_canonical_json(payload) != value:
            _fail(_INVALID)
    except (backup.BackupError, journal.JournalError) as error:
        raise AbandonError(_INVALID) from error
    result = deepcopy(value)
    result["backup_evidence"] = evidence
    return result


def _existing_receipt(transaction: Path) -> dict[str, Any] | None:
    path = transaction / ABANDONMENT_RECEIPT_FILE
    if not path.exists() and not path.is_symlink():
        return None
    payload, _metadata = _read_exact_file(path, links={1, 2})
    try:
        value = journal.parse_canonical_json(payload)
    except journal.JournalError as error:
        raise AbandonError(_INVALID) from error
    receipt = _validate_receipt(value)
    if payload != journal.canonical_json(receipt):
        _fail(_INVALID)
    return receipt


def _publish_receipt(
    transaction: Path,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    document = _validate_receipt(dict(receipt))
    payload = journal.canonical_json(document)
    final_name = ABANDONMENT_RECEIPT_FILE
    staging_name = ABANDONMENT_RECEIPT_STAGING_FILE
    with backup._open_transaction(transaction) as (
        _bound_transaction,
        descriptor,
        _binding,
    ):
        final_exists = backup._file_exists(descriptor, final_name)
        staging_exists = backup._file_exists(descriptor, staging_name)
        if staging_exists and not final_exists:
            observed, _metadata = _read_exact_file(
                transaction / staging_name,
                links={1},
            )
            if observed != payload:
                _fail(_INVALID)
            try:
                os.unlink(staging_name, dir_fd=descriptor)
                os.fsync(descriptor)
            except OSError as error:
                raise AbandonError(_INVALID) from error
            staging_exists = False
        if not final_exists:
            if staging_exists:
                _fail(_INVALID)
            backup._write_staging_file(descriptor, staging_name, payload)
            try:
                os.link(
                    staging_name,
                    final_name,
                    src_dir_fd=descriptor,
                    dst_dir_fd=descriptor,
                    follow_symlinks=False,
                )
                os.fsync(descriptor)
                os.unlink(staging_name, dir_fd=descriptor)
                os.fsync(descriptor)
            except OSError as error:
                raise AbandonError(_INVALID) from error
        elif staging_exists:
            final_payload, final_metadata = _read_exact_file(
                transaction / final_name,
                links={2},
            )
            staging_payload, staging_metadata = _read_exact_file(
                transaction / staging_name,
                links={2},
            )
            if (
                final_payload != payload
                or staging_payload != payload
                or (final_metadata.st_dev, final_metadata.st_ino)
                != (staging_metadata.st_dev, staging_metadata.st_ino)
            ):
                _fail(_INVALID)
            try:
                os.unlink(staging_name, dir_fd=descriptor)
                os.fsync(descriptor)
            except OSError as error:
                raise AbandonError(_INVALID) from error
        observed, metadata = _read_exact_file(
            transaction / final_name,
            links={1},
        )
        if observed != payload or metadata.st_nlink != 1:
            _fail(_INVALID)
    loaded = _existing_receipt(transaction)
    if loaded != document:
        _fail(_INVALID)
    return document


def _prove_no_later_transaction_artifacts(transaction: Path) -> None:
    try:
        entries = {entry.name for entry in transaction.iterdir()}
    except OSError as error:
        raise AbandonError(_INVALID) from error
    forbidden = {
        journal.RECEIPT_FILE,
        upgrade.SEALED_STATE_DIRECTORY,
    }
    if entries & forbidden or any(
        name.startswith("seal-attempt-") for name in entries
    ):
        _fail(_NOT_EXHAUSTED)


def _prove_old_units(
    transaction: Path,
    plan: Mapping[str, Any],
) -> dict[str, str]:
    try:
        old, _target = upgrade.unit_artifacts.load_unit_bundle_artifacts(
            transaction,
            plan["unit_artifacts"],
        )
        installed = upgrade.upgrade_systemd.snapshot_installed_units(
            Path(plan["finalize"]["unit_directory"])
        )
    except (
        upgrade.unit_artifacts.UnitArtifactError,
        upgrade.upgrade_systemd.UnitContractError,
    ) as error:
        raise AbandonError(_INVALID) from error
    if installed != old:
        _fail(_NOT_EXHAUSTED)
    return old.digests()


def _processing_gate_binding(
    gate: Mapping[str, Any],
) -> finalize.ProcessingGateBinding:
    try:
        binding = gate["operation_directory_binding"]
        inhibitor = gate["inhibitor"]
        value = finalize.ProcessingGateBinding(
            operation_directory=Path(gate["operation_directory"]),
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
        )
        return value.validated()
    except (KeyError, TypeError, finalize.FinalizeError) as error:
        raise AbandonError(_INVALID) from error


def _gate_state(binding: finalize.ProcessingGateBinding) -> str:
    operation = binding.operation_directory
    try:
        metadata = operation.lstat()
    except FileNotFoundError:
        return "absent"
    except OSError as error:
        raise AbandonError(_INVALID) from error
    if stat.S_ISLNK(metadata.st_mode) or not finalize._directory_matches(
        metadata,
        binding.directory_identity,
    ):
        _fail(_INVALID)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            operation,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        if not finalize._directory_matches(
            os.fstat(descriptor),
            binding.directory_identity,
        ):
            _fail(_INVALID)
        entries = set(os.listdir(descriptor))
        if not entries:
            return "empty"
        if entries != {reconciler.UPGRADE_INHIBITOR_FILE}:
            _fail(_INVALID)
        finalize._read_exact_marker(
            descriptor,
            reconciler._canonical(binding.inhibitor.document()),
            binding.directory_identity,
        )
        return "present"
    except AbandonError:
        raise
    except (OSError, finalize.FinalizeError) as error:
        raise AbandonError(_INVALID) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _prove_gate_absent_durable(
    binding: finalize.ProcessingGateBinding,
) -> None:
    operation = binding.operation_directory
    try:
        parent = reconciler._safe_directory(operation.parent)
        before = parent.lstat()
        descriptor = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except (OSError, reconciler.ReconcileError) as error:
        raise AbandonError(_INVALID) from error
    try:
        if not finalize._same_directory_binding(
            os.fstat(descriptor), before
        ) or not finalize._same_directory_binding(parent.lstat(), before):
            _fail(_INVALID)
        for proof in range(2):
            try:
                os.stat(
                    operation.name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                _fail(_INVALID)
            if proof == 0:
                os.fsync(descriptor)
        if not finalize._same_directory_binding(
            os.fstat(descriptor), before
        ) or not finalize._same_directory_binding(parent.lstat(), before):
            _fail(_INVALID)
    except AbandonError:
        raise
    except OSError as error:
        raise AbandonError(_INVALID) from error
    finally:
        os.close(descriptor)
    if _gate_state(binding) != "absent":
        _fail(_INVALID)


def _remove_gate(binding: finalize.ProcessingGateBinding) -> None:
    state = _gate_state(binding)
    if state == "absent":
        _prove_gate_absent_durable(binding)
        return
    operation = binding.operation_directory
    try:
        parent = reconciler._safe_directory(operation.parent)
        parent_metadata = parent.lstat()
    except (OSError, reconciler.ReconcileError) as error:
        raise AbandonError(_INVALID) from error
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
        if not finalize._same_directory_binding(
            os.fstat(parent_descriptor), parent_metadata
        ) or not finalize._same_directory_binding(
            parent.lstat(), parent_metadata
        ):
            _fail(_INVALID)
        operation_descriptor = os.open(
            operation.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        if not finalize._directory_matches(
            os.fstat(operation_descriptor), binding.directory_identity
        ):
            _fail(_INVALID)
        entries = set(os.listdir(operation_descriptor))
        if state == "present":
            if entries != {reconciler.UPGRADE_INHIBITOR_FILE}:
                _fail(_INVALID)
            finalize._read_exact_marker(
                operation_descriptor,
                reconciler._canonical(binding.inhibitor.document()),
                binding.directory_identity,
            )
            os.unlink(
                reconciler.UPGRADE_INHIBITOR_FILE,
                dir_fd=operation_descriptor,
            )
            os.fsync(operation_descriptor)
        elif state == "empty":
            if entries:
                _fail(_INVALID)
            # Durably re-prove the recognized post-marker-unlink crash state
            # before removing its exact empty directory.
            os.fsync(operation_descriptor)
        else:
            _fail(_INVALID)
        if os.listdir(operation_descriptor):
            _fail(_INVALID)
        current = os.stat(
            operation.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not finalize._directory_matches(
            current,
            binding.directory_identity,
        ):
            _fail(_INVALID)
        os.rmdir(operation.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except AbandonError:
        raise
    except (OSError, finalize.FinalizeError) as error:
        raise AbandonError(_INVALID) from error
    finally:
        if operation_descriptor is not None:
            os.close(operation_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
    _prove_gate_absent_durable(binding)


def _load_exact_source(
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], Path, dict[str, Any] | None]:
    try:
        source = Path(plan["source_state_directory"])
        desired, manifest, compose = reconciler._load_bound_state(source)
        activation = reconciler._load_activation(source, desired)
    except (KeyError, TypeError, reconciler.ReconcileError) as error:
        raise AbandonError(_INVALID) from error
    prepared = plan["prepared_desired"]
    maintenance = upgrade._expected_maintenance(prepared)
    if (
        desired not in (prepared, maintenance)
        or manifest.get("manifest_digest") != plan["source_manifest_digest"]
        or manifest.get("compose_digest") != plan["source_compose_digest"]
        or manifest.get("generation") != plan["source_generation"]
        or manifest.get("project") != plan["project"]
        or compose.parent.parent.name != "generations"
        or (
            activation is not None
            and activation.get("intent") != "running"
        )
    ):
        _fail(_NOT_EXHAUSTED)
    return desired, manifest, compose, activation


def _prove_original_deployment(
    plan: Mapping[str, Any],
    manifest: Mapping[str, Any],
    compose: Path,
    runner: Runner,
) -> dict[str, Any]:
    try:
        if not reconciler._docker_active(manifest, runner):
            _fail(_RECOVERY_FAILED)
        if reconciler._daemon_projection(manifest, runner) != manifest["daemon"]:
            _fail(_NOT_EXHAUSTED)
        deployment, healthy = reconciler._inspect_deployment(
            manifest,
            compose,
            runner,
        )
        if not healthy:
            _fail(_RECOVERY_FAILED)
        reconciler._smoke(manifest, public=False)
    except AbandonError:
        raise
    except reconciler.ReconcileError as error:
        raise AbandonError(_RECOVERY_FAILED) from error
    if deployment != {
        "containers": manifest["containers"],
        "resources": manifest["resources"],
    }:
        _fail(_NOT_EXHAUSTED)
    return deployment


def _without_docker_mutation(
    runner: Runner,
    manifest: Mapping[str, Any],
    compose: Path,
) -> Runner:
    """Allow only the exact Docker reads used by ``set_running``."""

    docker_prefix = tuple(reconciler._docker_prefix(manifest))
    compose_prefix = tuple(reconciler._compose_prefix(manifest, compose))
    systemctl = manifest["commands"]["systemctl"]
    docker_service = manifest["commands"]["docker_service"]

    def guarded(argv: Sequence[str], *, timeout: int = 30) -> bytes:
        command = tuple(argv)
        if command[:1] == docker_prefix[:1]:
            if command[: len(docker_prefix)] != docker_prefix:
                raise reconciler.ReconcileError("RECONCILE_STATE_CHANGED")
            tail = command[len(docker_prefix) :]
            read = (
                tail[:1] in {("info",), ("ps",)}
                or tail[:2]
                in {
                    ("container", "inspect"),
                    ("container", "ls"),
                    ("network", "inspect"),
                    ("network", "ls"),
                    ("volume", "inspect"),
                    ("volume", "ls"),
                }
                or (
                    command[: len(compose_prefix)] == compose_prefix
                    and command[len(compose_prefix) :][:1] == ("ps",)
                )
            )
            if not read:
                raise reconciler.ReconcileError("RECONCILE_STATE_CHANGED")
        if command[:1] == (systemctl,) and command != (
            systemctl,
            "--user",
            "is-active",
            "--quiet",
            "--",
            docker_service,
        ):
            raise reconciler.ReconcileError("RECONCILE_STATE_CHANGED")
        return runner(argv, timeout=timeout)

    return guarded


def _restore_original_running(
    plan_document: Mapping[str, Any],
    plan: Mapping[str, Any],
    progress: Mapping[str, Any],
    runner: Runner,
    lock_descriptor: int,
) -> dict[str, Any]:
    try:
        gate = upgrade._validate_processing_gate(
            progress["details"].get("processing_gate"),
            plan,
            plan_document["plan_digest"],
        )
    except upgrade.UpgradeError as error:
        raise AbandonError(_INVALID) from error
    binding = _processing_gate_binding(gate)
    desired, manifest, compose, activation = _load_exact_source(plan)
    deployment = _prove_original_deployment(plan, manifest, compose, runner)
    gate_state = _gate_state(binding)
    if gate_state == "present":
        try:
            if (
                desired == upgrade._expected_maintenance(
                    plan["prepared_desired"]
                )
                and activation is None
            ):
                _status, public = reconciler._tailnet_state(
                    manifest,
                    compose,
                    runner,
                )
                if public:
                    _fail(_NOT_EXHAUSTED)
            upgrade._validate_processing_gate(
                gate,
                plan,
                plan_document["plan_digest"],
                manifest=manifest,
                require_live=True,
            )
            reconciler.set_running(
                Path(plan["source_state_directory"]),
                runner=_without_docker_mutation(runner, manifest, compose),
                lock_descriptor=lock_descriptor,
                upgrade_inhibitor=gate["inhibitor"],
            )
        except (upgrade.UpgradeError, reconciler.ReconcileError) as error:
            raise AbandonError(_RECOVERY_FAILED) from error
    elif desired != plan["prepared_desired"] or activation is not None:
        _fail(_INVALID)
    desired, manifest, compose, activation = _load_exact_source(plan)
    if desired != plan["prepared_desired"] or activation is not None:
        _fail(_RECOVERY_FAILED)
    deployment = _prove_original_deployment(plan, manifest, compose, runner)
    try:
        _status, public = reconciler._tailnet_state(manifest, compose, runner)
        if not public:
            _fail(_RECOVERY_FAILED)
        reconciler._smoke(manifest, public=True)
    except AbandonError:
        raise
    except reconciler.ReconcileError as error:
        raise AbandonError(_RECOVERY_FAILED) from error
    if gate_state in {"present", "empty"}:
        _remove_gate(binding)
    try:
        _prove_gate_absent_durable(binding)
    except AbandonError as error:
        raise AbandonError(_RECOVERY_FAILED) from error
    desired, manifest, compose, activation = _load_exact_source(plan)
    if desired != plan["prepared_desired"] or activation is not None:
        _fail(_RECOVERY_FAILED)
    final_deployment = _prove_original_deployment(
        plan,
        manifest,
        compose,
        runner,
    )
    if final_deployment != deployment:
        _fail(_STATE_CHANGED)
    try:
        _status, public = reconciler._tailnet_state(manifest, compose, runner)
        if not public:
            _fail(_RECOVERY_FAILED)
        reconciler._smoke(manifest, public=True)
    except AbandonError:
        raise
    except reconciler.ReconcileError as error:
        raise AbandonError(_RECOVERY_FAILED) from error
    return {
        "compose_digest": manifest["compose_digest"],
        "deployment_digest": reconciler._digest(
            reconciler._canonical(final_deployment)
        ),
        "generation": manifest["generation"],
        "manifest_digest": manifest["manifest_digest"],
        "state_digest": desired["state_digest"],
    }


def _receipt_document(
    expected_active: Mapping[str, str],
    plan_document: Mapping[str, Any],
    progress: Mapping[str, Any],
    backup_evidence: Mapping[str, Any],
    source: Mapping[str, Any],
    unit_digests: Mapping[str, str],
    inhibitor_digest: str,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "active_selector_digest": expected_active["active_digest"],
        "backup_evidence": deepcopy(backup_evidence),
        "contract_version": ABANDONMENT_CONTRACT,
        "operation_id": expected_active["operation_id"],
        "phase": upgrade.BACKING_UP,
        "plan_digest": plan_document["plan_digest"],
        "processing_gate": {
            "inhibitor_digest": inhibitor_digest,
            "status": "absent",
        },
        "progress_digest": progress["progress_digest"],
        "progress_sequence": progress["sequence"],
        "reason": REASON,
        "receipt_digest": "",
        "source": dict(source),
        "status": "abandoned",
        "unit_digests": dict(unit_digests),
    }
    value["receipt_digest"] = _document_digest(value, "receipt_digest")
    return _validate_receipt(value)


def _selector_state(
    upgrades: Path,
    transaction: Path,
    expected: Mapping[str, str],
) -> str:
    payload = journal.canonical_json(expected)
    active = upgrades / upgrade.ACTIVE_FILE
    retired = transaction / RETIRED_ACTIVE_FILE
    active_exists = active.exists() or active.is_symlink()
    retired_exists = retired.exists() or retired.is_symlink()
    if not retired_exists:
        if not active_exists:
            _fail(_STATE_CHANGED)
        observed, metadata = _read_exact_file(active, links={1})
        if observed != payload or metadata.st_nlink != 1:
            _fail(_STATE_CHANGED)
        return "active"
    retired_payload, retired_metadata = _read_exact_file(
        retired,
        links={1, 2},
    )
    if retired_payload != payload:
        _fail(_STATE_CHANGED)
    if not active_exists:
        if retired_metadata.st_nlink != 1:
            _fail(_STATE_CHANGED)
        return "retired"
    active_payload, active_metadata = _read_exact_file(active, links={2})
    if (
        active_payload != payload
        or retired_metadata.st_nlink != 2
        or (active_metadata.st_dev, active_metadata.st_ino)
        != (retired_metadata.st_dev, retired_metadata.st_ino)
    ):
        _fail(_STATE_CHANGED)
    return "linked"


def _retire_active(
    upgrades: Path,
    transaction: Path,
    expected: Mapping[str, str],
) -> None:
    with upgrade._active_directory_lock(upgrades):
        upgrade._repair_active_publication_locked(upgrades)
        state = _selector_state(upgrades, transaction, expected)
        active = upgrades / upgrade.ACTIVE_FILE
        retired = transaction / RETIRED_ACTIVE_FILE
        if state == "active":
            try:
                os.link(active, retired, follow_symlinks=False)
                reconciler._fsync_directory(transaction)
            except FileExistsError as error:
                raise AbandonError(_STATE_CHANGED) from error
            except OSError as error:
                raise AbandonError(_INVALID) from error
            state = _selector_state(upgrades, transaction, expected)
        if state == "linked":
            # A retry may enter after link(2) but before its directory fsync.
            # Make the retained selector durable before removing the active
            # name, then re-prove the exact two-link state.
            reconciler._fsync_directory(transaction)
            if _selector_state(upgrades, transaction, expected) != "linked":
                _fail(_STATE_CHANGED)
            try:
                active.unlink()
                reconciler._fsync_directory(upgrades)
            except OSError as error:
                raise AbandonError(_INVALID) from error
        elif state == "retired":
            # Repair the unlink-before-parent-fsync crash window by durably
            # reasserting the already-absent active name.
            reconciler._fsync_directory(upgrades)
        if _selector_state(upgrades, transaction, expected) != "retired":
            _fail(_STATE_CHANGED)


def abandon_exhausted_backup(
    state_parent: Path,
    operation_id: str,
    *,
    serial_lock_file: Path | None = None,
    runner: Runner | None = None,
    lock_descriptor: int | None = None,
) -> dict[str, str]:
    """Terminally abandon one exact exhausted, pre-replacement transaction."""

    try:
        parent = reconciler._safe_directory(
            upgrade._canonical_path(state_parent, _INVALID)
        )
    except (upgrade.UpgradeError, reconciler.ReconcileError) as error:
        raise AbandonError(_INVALID) from error
    with upgrade._upgrade_serialization_lock(
        parent,
        serial_lock_file,
    ) as (_serial_descriptor, serial_binding, _serial_path):
        initial = _load_operation(parent, operation_id)
        (
            upgrades,
            transaction,
            plan_document,
            plan,
            progress,
            expected_active,
        ) = initial
        sealed_serial = upgrade._validated_lock_binding(
            plan["serial_lock"],
            parent / upgrade.SERIAL_LOCK_FILE,
            _INVALID,
        )
        if not reconciler._record_matches_binding(serial_binding, sealed_serial):
            _fail(_INVALID)
        with upgrade._deployment_lock(plan["project"], lock_descriptor) as lock:
            current = _load_operation(parent, operation_id)
            if current != initial:
                _fail(_STATE_CHANGED)
            with upgrade._active_directory_lock(upgrades):
                upgrade._repair_active_publication_locked(upgrades)
                state = _selector_state(upgrades, transaction, expected_active)
            existing = _existing_receipt(transaction)
            if state == "retired" and existing is None:
                _fail(_INVALID)
            _prove_no_later_transaction_artifacts(transaction)
            unit_digests = _prove_old_units(transaction, plan)
            try:
                bindings = upgrade._backup_bindings(plan_document, plan)
                backup_evidence = backup.validate_exhausted_backup_evidence(
                    transaction,
                    bindings,
                )
            except (upgrade.UpgradeError, backup.BackupError) as error:
                raise AbandonError(_NOT_EXHAUSTED) from error
            selected_runner = runner
            if selected_runner is None:
                try:
                    _desired, manifest, _compose, _activation = (
                        _load_exact_source(plan)
                    )
                    selected_runner = reconciler._runner_for_manifest(manifest)
                except reconciler.ReconcileError as error:
                    raise AbandonError(_RECOVERY_FAILED) from error
            source = _restore_original_running(
                plan_document,
                plan,
                progress,
                selected_runner,
                lock,
            )
            receipt = _receipt_document(
                expected_active,
                plan_document,
                progress,
                backup_evidence,
                source,
                unit_digests,
                progress["details"]["processing_gate"]["inhibitor"][
                    "inhibitor_digest"
                ],
            )
            if existing is not None and existing != receipt:
                _fail(_STATE_CHANGED)
            receipt = _publish_receipt(transaction, receipt)
            _retire_active(upgrades, transaction, expected_active)
            loaded = _existing_receipt(transaction)
            if loaded != receipt:
                _fail(_INVALID)
            return {
                "code": "REVIEWER_UPGRADE_ABANDONED",
                "operation_id": operation_id,
                "status": "abandoned",
            }


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    parser.add_argument("--state-parent", required=True, type=Path)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--serial-lock-file", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o077)
    try:
        args = _parser().parse_args(argv)
        result = abandon_exhausted_backup(
            args.state_parent,
            args.operation_id,
            serial_lock_file=args.serial_lock_file,
        )
        sys.stdout.buffer.write(journal.canonical_json(result) + b"\n")
        return 0
    except AbandonError as error:
        code = error.code
    except (
        backup.BackupError,
        finalize.FinalizeError,
        journal.JournalError,
        reconciler.ReconcileError,
        upgrade.UpgradeError,
    ):
        code = _INVALID
    except (OSError, TypeError, ValueError):
        code = _INVALID
    sys.stderr.buffer.write(
        journal.canonical_json({"code": code, "status": "failed"}) + b"\n"
    )
    return 1 if code == _RECOVERY_FAILED else 78


if __name__ == "__main__":
    raise SystemExit(main())
