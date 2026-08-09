# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from contextlib import nullcontext
from copy import deepcopy
import ast
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "services/backend/scripts/reviewer_upgrade_transaction.py"
ABANDON_SCRIPT = ROOT / "services/backend/scripts/reviewer_upgrade_abandon.py"


def _load_script():
    specification = importlib.util.spec_from_file_location(
        "tacua_reviewer_upgrade_transaction_test",
        SCRIPT,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("reviewer upgrade transaction cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


UPGRADE = _load_script()


def _load_abandon_script():
    specification = importlib.util.spec_from_file_location(
        "tacua_reviewer_upgrade_abandon_test",
        ABANDON_SCRIPT,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("reviewer upgrade abandon cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


ABANDON = _load_abandon_script()


OLD_IMAGE_ID = "sha256:" + "1" * 64
CANDIDATE_IMAGE_ID = "sha256:" + "2" * 64
BACKEND_IMAGE_ID = "sha256:" + "5" * 64
OLD_REVIEWER_ID = "a" * 64
CANDIDATE_REVIEWER_ID = "d" * 64
BACKEND_ID = "b" * 64
INGRESS_ID = "c" * 64


class ReviewerUpgradeTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.boot_id = "00000000-0000-4000-8000-000000000001"
        boot = mock.patch.object(
            UPGRADE,
            "_current_boot_id",
            return_value=self.boot_id,
        )
        boot.start()
        self.addCleanup(boot.stop)
        serial_lock = self.root / UPGRADE.SERIAL_LOCK_FILE
        serial_lock.touch(mode=0o600, exist_ok=False)
        serial_lock.chmod(0o600)

    def _fixture(
        self,
        *,
        desired_state: str = "running",
        candidate_change: tuple[str, object] | None = None,
    ) -> tuple[Path, Path]:
        state = self.root / "state"
        state.mkdir(mode=0o700)
        operations = self.root / "operations"
        operations.mkdir(mode=0o700)
        config = self.root / "config.json"
        config.write_text("{}", encoding="ascii")
        config.chmod(0o644)
        secret = self.root / "admin-secret"
        secret.write_text("synthetic-secret\n", encoding="ascii")
        secret.chmod(0o444)
        source_repository = self.root / "source-repository"
        candidate_repository = self.root / "candidate-repository"
        for repository in (source_repository, candidate_repository):
            ingress = repository / UPGRADE.INGRESS_CONFIG_SUFFIX
            ingress.parent.mkdir(mode=0o700, parents=True)
            ingress.write_bytes(b"synthetic ingress\n")
            ingress.chmod(0o600)
        candidate_backend = candidate_repository / "services" / "backend"
        candidate_scripts = candidate_backend / "scripts"
        candidate_scripts.mkdir(mode=0o700)
        shutil.copy2(
            ROOT
            / "services"
            / "backend"
            / "scripts"
            / "reconcile_compose_deployment.py",
            candidate_scripts / "reconcile_compose_deployment.py",
        )
        shutil.copytree(
            ROOT / "services" / "backend" / "systemd",
            candidate_backend / "systemd",
        )
        source_document = {
            "configs": {
                "tacua_loopback_ingress": {
                    "file": str(
                        source_repository / UPGRADE.INGRESS_CONFIG_SUFFIX
                    ),
                    "name": "reconcile-test_tacua_loopback_ingress",
                }
            },
            "name": "reconcile-test",
            "networks": {
                "private": {"name": "reconcile-test_private"},
                "publish": {"name": "reconcile-test_publish"},
            },
            "services": {
                "backend": {"image": "tacua-backend:local"},
                "ingress": {"image": "haproxy@example"},
                "reviewer": {"image": "tacua-reviewer-web:old"},
            },
            "volumes": {
                "tacua-state": {"name": "reconcile-test_tacua-state"}
            },
        }
        candidate_document = deepcopy(source_document)
        candidate_document["services"]["reviewer"]["image"] = (
            "tacua-reviewer-web:candidate"
        )
        candidate_document["configs"]["tacua_loopback_ingress"]["file"] = str(
            candidate_repository / UPGRADE.INGRESS_CONFIG_SUFFIX
        )
        if candidate_change is not None:
            key, value = candidate_change
            candidate_document["services"]["reviewer"][key] = value

        generation = state / "generations" / "generation-1"
        generation.mkdir(mode=0o700, parents=True)
        (state / "generations").chmod(0o700)
        source_payload = UPGRADE.reconciler._canonical(source_document)
        source_compose = generation / UPGRADE.reconciler.COMPOSE_FILE
        source_compose.write_bytes(source_payload)
        source_compose.chmod(0o400)
        manifest = {
            "commands": {
                "docker": "/usr/bin/docker",
                "docker_service": "docker.service",
                "systemctl": "/usr/bin/systemctl",
                "tailscale": "/usr/bin/tailscale",
            },
            "compose_digest": UPGRADE.reconciler._digest(source_payload),
            "config": UPGRADE.reconciler._identity(config, secret=False),
            "containers": {
                "backend": {
                    "config": {"Image": "tacua-backend:local"},
                    "id": BACKEND_ID,
                    "image_id": BACKEND_IMAGE_ID,
                    "mounts": [
                        {
                            "Destination": "/var/lib/tacua",
                            "Name": "reconcile-test_tacua-state",
                            "RW": True,
                            "Type": "volume",
                        }
                    ],
                },
                "ingress": {"id": INGRESS_ID},
                "reviewer": {"id": OLD_REVIEWER_ID},
            },
            "contract_version": UPGRADE.reconciler.GENERATION_CONTRACT,
            "daemon": {
                "cgroup_driver": "systemd",
                "cgroup_version": "2",
                "docker_root_directory": "/private/docker",
                "id": "synthetic-rootless-daemon",
                "security_options": [
                    "name=rootless",
                    "name=seccomp,profile=builtin",
                ],
            },
            "generation": "generation-1",
            "manifest_digest": "",
            "operation_directory": str(operations),
            "project": "reconcile-test",
            "published_port": 8080,
            "resources": {"networks": {}, "volumes": {}},
            "runtime": {
                "docker_host": "unix:///run/user/501/docker.sock",
                "home": "/private/home",
                "xdg_runtime_directory": "/run/user/501",
            },
            "secret": UPGRADE.reconciler._identity(secret, secret=True),
        }
        manifest["manifest_digest"] = UPGRADE.reconciler._document_digest(
            manifest,
            "manifest_digest",
        )
        manifest_path = generation / UPGRADE.reconciler.MANIFEST_FILE
        manifest_path.write_bytes(UPGRADE.reconciler._canonical(manifest))
        manifest_path.chmod(0o600)
        desired = {
            "compose_digest": manifest["compose_digest"],
            "contract_version": UPGRADE.reconciler.DESIRED_CONTRACT,
            "desired": desired_state,
            "generation": manifest["generation"],
            "manifest_digest": manifest["manifest_digest"],
            "project": manifest["project"],
            "state_digest": "",
        }
        desired["state_digest"] = UPGRADE.reconciler._document_digest(
            desired,
            "state_digest",
        )
        desired_path = state / UPGRADE.reconciler.DESIRED_FILE
        desired_path.write_bytes(UPGRADE.reconciler._canonical(desired))
        desired_path.chmod(0o600)
        candidate = self.root / "candidate-compose.json"
        candidate.write_bytes(UPGRADE.reconciler._canonical(candidate_document))
        candidate.chmod(0o600)
        unit_directory = self.root / "user-units"
        unit_directory.mkdir(mode=0o700)
        for name in UPGRADE.upgrade_systemd.UNIT_NAMES:
            unit = unit_directory / name
            unit.write_bytes(f"old:{name}\n".encode("ascii"))
            unit.chmod(0o600)
        return state, candidate

    def _candidate_documents(
        self,
        state: Path,
        candidate: Path,
    ) -> tuple[dict, dict]:
        _desired, _manifest, source_compose = (
            UPGRADE.reconciler._load_bound_state(state)
        )
        return (
            UPGRADE.reconciler._parse_json(
                source_compose.read_bytes(),
                "REVIEWER_UPGRADE_STATE_INVALID",
            ),
            UPGRADE.reconciler._parse_json(
                candidate.read_bytes(),
                "REVIEWER_UPGRADE_CANDIDATE_INVALID",
            ),
        )

    def _upgrade_abi(self, state: Path) -> dict[str, Path]:
        _desired, manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        return {
            "unit_directory": self.root / "user-units",
            "lock_file": UPGRADE.reconciler._lock_path(manifest["project"]),
            "operation_directory": Path(manifest["operation_directory"]),
        }

    def _test_lock_binding(self, state: Path) -> dict[str, object]:
        lock_file = self._upgrade_abi(state)["lock_file"]
        return {
            "device": 1,
            "inode": 1,
            "mode": 0o600,
            "path": str(lock_file),
            "uid": os.geteuid(),
        }

    def _runner(self, argv, *, timeout):
        if argv[-5:-2] == ["image", "inspect", "--format"]:
            return (CANDIDATE_IMAGE_ID + "\n").encode("ascii")
        raise AssertionError((argv, timeout))

    def _prepare(
        self,
        *,
        desired_state: str = "running",
        drive_gate: bool = True,
    ) -> tuple[Path, Path, Path, dict, dict]:
        state, candidate = self._fixture(desired_state=desired_state)
        desired, manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        deployment = {
            "containers": manifest["containers"],
            "resources": manifest["resources"],
        }
        with mock.patch.object(
            UPGRADE,
            "_prepare_live_preconditions",
            return_value=deployment,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_host_lock",
            return_value=91,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_release_lock",
        ), mock.patch.object(
            UPGRADE,
            "_bound_lock_file",
            return_value=self._test_lock_binding(state),
        ), (
            nullcontext()
            if drive_gate
            else mock.patch.object(
                UPGRADE,
                "_drive_processing_gate",
                side_effect=(
                    lambda _transaction, _document, _plan, progress, _manifest: (
                        progress,
                        {},
                    )
                ),
            )
        ):
            result = UPGRADE.prepare(
                state,
                candidate,
                **self._upgrade_abi(state),
                runner=self._runner,
                operation_id="reviewer-test-operation",
            )
        upgrades = self.root / UPGRADE.UPGRADES_DIRECTORY
        active = UPGRADE._load_active(upgrades)
        assert active is not None
        transaction, plan_document, plan, progress = UPGRADE._load_transaction(
            upgrades,
            active,
        )
        self.assertEqual(
            progress["phase"],
            UPGRADE.QUIESCING if drive_gate else UPGRADE.PREPARED,
        )
        if drive_gate:
            self.assertEqual(
                progress["details"]["gate_state"],
                UPGRADE.GATE_INHIBITOR_READY,
            )
        self.assertEqual(
            plan["source_repository_root"],
            str(self.root / "source-repository"),
        )
        self.assertEqual(
            plan["candidate_repository_root"],
            str(self.root / "candidate-repository"),
        )
        self.assertEqual(result["operation_id"], plan["operation_id"])
        self.assertEqual(desired["desired"], desired_state)
        return state, candidate, transaction, plan_document, plan

    def _prepare_with_real_processing_lock(
        self,
        processing_lock: Path,
    ) -> tuple[Path, Path, Path, dict, dict]:
        state, candidate = self._fixture()
        _desired, manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        deployment = {
            "containers": manifest["containers"],
            "resources": manifest["resources"],
        }
        abi = self._upgrade_abi(state)
        abi["lock_file"] = processing_lock
        with mock.patch.object(
            UPGRADE,
            "_prepare_live_preconditions",
            return_value=deployment,
        ):
            UPGRADE.prepare(
                state,
                candidate,
                **abi,
                runner=self._runner,
                operation_id="reviewer-real-lock-operation",
            )
        upgrades = self.root / UPGRADE.UPGRADES_DIRECTORY
        active = UPGRADE._load_active(upgrades)
        assert active is not None
        transaction, plan_document, plan, _progress = UPGRADE._load_transaction(
            upgrades,
            active,
        )
        return state, candidate, transaction, plan_document, plan

    @staticmethod
    def _leave_processing_gate_uncheckpointed(
        _transaction,
        _plan_document,
        _plan,
        progress,
        _manifest,
    ):
        return progress, {}

    def _replace_processing_lock_inode(self, path: Path) -> os.stat_result:
        original = path.lstat()
        path.unlink()
        # Keep any immediately recycled inode occupied so the replacement is
        # observably distinct even on small temporary filesystems.
        filler = self.root / f"lock-inode-filler-{original.st_ino}"
        filler.touch(mode=0o600, exist_ok=False)
        filler.chmod(0o600)
        path.touch(mode=0o600, exist_ok=False)
        path.chmod(0o600)
        replacement = path.lstat()
        self.assertNotEqual(
            (replacement.st_dev, replacement.st_ino),
            (original.st_dev, original.st_ino),
        )
        return replacement

    def _set_maintenance(self, state: Path) -> None:
        desired_path = state / UPGRADE.reconciler.DESIRED_FILE
        desired = json.loads(desired_path.read_text(encoding="ascii"))
        desired["desired"] = "maintenance"
        desired["state_digest"] = UPGRADE.reconciler._document_digest(
            desired,
            "state_digest",
        )
        desired_path.write_bytes(UPGRADE.reconciler._canonical(desired))
        desired_path.chmod(0o600)

    def _progress(self, transaction: Path, plan_document: dict) -> dict:
        progress = UPGRADE.journal.load_progress(transaction, plan_document)
        assert progress is not None
        return progress

    def _gate(self, transaction: Path, plan_document: dict, plan: dict) -> dict:
        progress = self._progress(transaction, plan_document)
        return UPGRADE._processing_gate_from_quiescing(
            progress["details"],
            plan,
            plan_document["plan_digest"],
        )

    def _fake_maintenance_proof(
        self,
        plan: dict,
        _plan_digest: str,
        gate: dict,
        desired: dict,
        _manifest: dict,
        _compose: Path,
        _runner,
    ) -> dict:
        self.assertEqual(desired["desired"], "maintenance")
        self.assertEqual(
            desired,
            UPGRADE._expected_maintenance(plan["prepared_desired"]),
        )
        return UPGRADE._maintenance_details(
            gate,
            desired,
            {"synthetic": "maintenance-deployment"},
        )

    def _prepare_bound_gate(
        self,
    ) -> tuple[Path, Path, dict, dict, dict, Path, dict, dict]:
        state, _candidate, transaction, plan_document, plan = self._prepare(
            drive_gate=False
        )
        _desired, manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        operation = UPGRADE._inhibitor_path(manifest)
        progress = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.QUIESCING,
            UPGRADE._quiescing_details(UPGRADE.GATE_PENDING, operation),
        )
        operation.mkdir(mode=0o700)
        UPGRADE.reconciler._fsync_directory(operation.parent)
        binding = UPGRADE._operation_directory_binding(operation)
        progress = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.QUIESCING,
            UPGRADE._quiescing_details(
                UPGRADE.GATE_DIRECTORY_BOUND,
                operation,
                binding=binding,
            ),
        )
        return (
            state,
            transaction,
            plan_document,
            plan,
            manifest,
            operation,
            binding,
            progress,
        )

    def _backup_receipt(self, plan_document: dict, plan: dict) -> dict:
        bindings = UPGRADE._backup_bindings(plan_document, plan)
        receipt = {
            "attempt": {
                "number": 1,
                "relative_path": "backup-attempt-01",
            },
            "backend": {
                "container_id": bindings.backend_container_id,
                "image_id": bindings.backend_image_id,
                "image_ref": bindings.backend_image_ref,
                "state_volume": bindings.state_volume,
            },
            "bindings_digest": UPGRADE.backup._bindings_digest(bindings),
            "bundle": {
                "durable": True,
                "relative_path": UPGRADE.backup.BACKUP_BUNDLE_DIRECTORY,
                "sha256": "sha256:" + "6" * 64,
                "verified": True,
            },
            "contract_version": UPGRADE.backup.BACKUP_RECEIPT_CONTRACT,
            "plan_digest": plan_document["plan_digest"],
            "prior_attempts": [],
            "receipt_digest": "",
            "status": "backup_ready",
        }
        receipt["receipt_digest"] = UPGRADE.backup._document_digest(
            receipt,
            "receipt_digest",
        )
        return UPGRADE.backup.validate_backup_receipt(receipt, bindings)

    def _finalize_receipt(
        self,
        operation: str,
        status: str,
        details: dict,
    ) -> dict:
        receipt = {
            "contract_version": UPGRADE.finalize.RECEIPT_CONTRACT,
            "details": details,
            "generation": "generation-2",
            "operation": operation,
            "project": "reconcile-test",
            "receipt_digest": "",
            "status": status,
        }
        receipt["receipt_digest"] = UPGRADE.reconciler._document_digest(
            receipt,
            "receipt_digest",
        )
        return receipt

    def _finalization_evidence(self, gate: dict) -> dict[str, object]:
        target_digests = {
            name: "sha256:" + character * 64
            for name, character in zip(
                UPGRADE.upgrade_systemd.UNIT_NAMES,
                ("7", "8", "9"),
                strict=True,
            )
        }
        return {
            "target_digests": target_digests,
            "promotion": self._finalize_receipt(
                "promote_target_maintenance",
                "maintenance_ready",
                {"target_unit_digests": target_digests},
            ),
            "activation": self._finalize_receipt(
                "activate_target",
                "running_gate_held",
                {
                    "inhibitor_digest": gate["inhibitor"][
                        "inhibitor_digest"
                    ]
                },
            ),
            "removal": self._finalize_receipt(
                "remove_processing_gate",
                "gate_absent",
                {
                    "inhibitor_digest": gate["inhibitor"][
                        "inhibitor_digest"
                    ]
                },
            ),
            "scheduled": self._finalize_receipt(
                "prove_later_scheduled_reconcile",
                "scheduled_reconcile_proven",
                {"invocation_id": "c" * 32},
            ),
        }

    def _complete_finalization_details(
        self,
        gate: dict,
        evidence: dict[str, object],
    ) -> dict[str, object]:
        return {
            "activation_receipt": evidence["activation"],
            "gate_removal_receipt": evidence["removal"],
            "processing_gate": gate,
            "promotion_receipt": evidence["promotion"],
            "scheduled_receipt": evidence["scheduled"],
        }

    def _checkpoint_maintenance(
        self,
    ) -> tuple[Path, Path, dict, dict, dict, dict, dict, Path]:
        state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        self._set_maintenance(state)
        desired, manifest, compose = UPGRADE.reconciler._load_bound_state(state)
        details = self._fake_maintenance_proof(
            plan,
            plan_document["plan_digest"],
            gate,
            desired,
            manifest,
            compose,
            mock.Mock(),
        )
        progress = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.MAINTENANCE,
            details,
        )
        return (
            state,
            transaction,
            plan_document,
            plan,
            progress,
            desired,
            manifest,
            compose,
        )

    def _checkpoint_exhausted_backup(
        self,
    ) -> tuple[Path, Path, dict, dict, dict, dict]:
        (
            state,
            transaction,
            plan_document,
            plan,
            maintenance,
            _desired,
            _manifest,
            _compose,
        ) = self._checkpoint_maintenance()
        gate = maintenance["details"]["processing_gate"]
        progress = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.BACKING_UP,
            {"processing_gate": gate},
        )
        bindings = UPGRADE._backup_bindings(plan_document, plan)
        with UPGRADE.backup._open_transaction(transaction) as (
            bound_transaction,
            descriptor,
            _binding,
        ):
            ledger = UPGRADE.backup._load_or_create_ledger(
                descriptor,
                bindings,
            )
            for number in range(1, UPGRADE.backup.MAX_BACKUP_ATTEMPTS + 1):
                UPGRADE.backup._create_attempt(
                    bound_transaction,
                    descriptor,
                    bindings,
                    number,
                )
                UPGRADE.backup._quarantine_attempt(
                    bound_transaction,
                    descriptor,
                    bindings,
                    number,
                )
                ledger = UPGRADE.backup._append_ledger_entry(
                    descriptor,
                    bindings,
                    ledger,
                    number,
                    "failed",
                )
        return state, transaction, plan_document, plan, progress, gate

    def _set_running(self, state: Path) -> None:
        desired_path = state / UPGRADE.reconciler.DESIRED_FILE
        desired = json.loads(desired_path.read_text(encoding="ascii"))
        desired["desired"] = "running"
        desired["state_digest"] = UPGRADE.reconciler._document_digest(
            desired,
            "state_digest",
        )
        desired_path.write_bytes(UPGRADE.reconciler._canonical(desired))
        desired_path.chmod(0o600)

    def _abandon_patches(self, state: Path):
        _desired, manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        deployment = {
            "containers": manifest["containers"],
            "resources": manifest["resources"],
        }

        def set_running(
            selected_state,
            *,
            runner,
            lock_descriptor,
            upgrade_inhibitor,
        ):
            self.assertEqual(selected_state, state)
            self.assertEqual(lock_descriptor, 79)
            self.assertIsNotNone(runner)
            self.assertEqual(upgrade_inhibitor["project"], manifest["project"])
            self._set_running(state)
            return {"code": "RECONCILE_RECOVERED", "status": "recovered"}

        def tailnet_state(_manifest, _compose, _runner):
            desired, _current_manifest, _current_compose = (
                UPGRADE.reconciler._load_bound_state(state)
            )
            return {}, desired["desired"] == "running"

        return (
            mock.patch.object(
                ABANDON.upgrade,
                "_deployment_lock",
                return_value=nullcontext(79),
            ),
            mock.patch.object(
                ABANDON,
                "_prove_original_deployment",
                return_value=deployment,
            ),
            mock.patch.object(
                ABANDON.reconciler,
                "set_running",
                side_effect=set_running,
            ),
            mock.patch.object(
                ABANDON.reconciler,
                "_tailnet_state",
                side_effect=tailnet_state,
            ),
            mock.patch.object(ABANDON.reconciler, "_smoke"),
        )

    def _checkpoint_active_sealing(
        self,
    ) -> tuple[Path, Path, dict, dict, dict, dict, dict]:
        state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        self._set_maintenance(state)
        _desired, manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        ready = {
            "candidate_container_id": CANDIDATE_REVIEWER_ID,
            "candidate_image_id": CANDIDATE_IMAGE_ID,
            "deployment_digest": "sha256:" + "8" * 64,
            "processing_gate": gate,
        }
        UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.REPLACING,
            {
                "candidate_image_id": CANDIDATE_IMAGE_ID,
                "initial_classification": UPGRADE.OLD,
                "processing_gate": gate,
            },
        )
        UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.REVIEWER_READY,
            ready,
        )
        attempt = UPGRADE._attempt_record(transaction, 1)
        progress = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.SEALING,
            UPGRADE._sealing_details(
                ready,
                [attempt],
                [],
                1,
                plan["sealed_state_directory"],
            ),
        )
        return (
            transaction,
            plan_document,
            plan,
            manifest,
            ready,
            attempt,
            progress,
        )

    def test_prepare_publishes_plan_active_and_inhibitor_before_mutation(self) -> None:
        state, candidate, transaction, plan_document, plan = self._prepare()

        active_path = self.root / UPGRADE.UPGRADES_DIRECTORY / UPGRADE.ACTIVE_FILE
        self.assertEqual(stat.S_IMODE(active_path.lstat().st_mode), 0o600)
        self.assertEqual(active_path.lstat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(transaction.lstat().st_mode), 0o700)
        candidate_copy = transaction / UPGRADE.CANDIDATE_COMPOSE_FILE
        self.assertEqual(candidate_copy.read_bytes(), candidate.read_bytes())
        self.assertEqual(stat.S_IMODE(candidate_copy.lstat().st_mode), 0o600)
        self.assertEqual(plan["prepared_desired"]["desired"], "running")
        self.assertEqual(
            plan["sealed_state_directory"],
            str(transaction / UPGRADE.SEALED_STATE_DIRECTORY),
        )
        self.assertEqual(len(plan["unit_artifacts"]), 6)
        old_units, target_units = (
            UPGRADE.unit_artifacts.load_unit_bundle_artifacts(
                transaction,
                plan["unit_artifacts"],
            )
        )
        self.assertEqual(
            old_units.payloads(),
            {
                name: f"old:{name}\n".encode("ascii")
                for name in UPGRADE.upgrade_systemd.UNIT_NAMES
            },
        )
        self.assertNotEqual(target_units.digests(), old_units.digests())
        for descriptor in plan["unit_artifacts"]:
            sidecar = transaction / descriptor["relative_path"]
            self.assertEqual(stat.S_IMODE(sidecar.lstat().st_mode), 0o600)
            self.assertEqual(sidecar.lstat().st_nlink, 1)
        self.assertEqual(
            plan["finalize"]["reconcile_bindings"]["state_directory"],
            plan["sealed_state_directory"],
        )
        self.assertEqual(
            plan["finalize"]["reconcile_bindings"]["reconciler"],
            str(
                self.root
                / "candidate-repository"
                / "services"
                / "backend"
                / "scripts"
                / "reconcile_compose_deployment.py"
            ),
        )
        self.assertEqual(
            plan["finalize"]["unit_directory"],
            str(self.root / "user-units"),
        )

        _desired, manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        inhibitor_path = (
            Path(manifest["operation_directory"])
            / "tacua-compose-processing-reconcile-test"
            / UPGRADE.INHIBITOR_FILE
        )
        inhibitor = UPGRADE.journal.parse_canonical_json(
            inhibitor_path.read_bytes()
        )
        self.assertEqual(inhibitor["plan_digest"], plan_document["plan_digest"])
        self.assertEqual(
            inhibitor["inhibitor_digest"],
            UPGRADE.reconciler._document_digest(
                inhibitor,
                "inhibitor_digest",
            ),
        )
        progress = self._progress(transaction, plan_document)
        self.assertEqual(progress["phase"], UPGRADE.QUIESCING)
        self.assertEqual(
            progress["details"]["gate_state"],
            UPGRADE.GATE_INHIBITOR_READY,
        )
        self.assertEqual(
            progress["details"]["operation_directory_binding"],
            UPGRADE._operation_directory_binding(inhibitor_path.parent),
        )

    def test_prepare_renders_finalize_units_from_candidate_repository(self) -> None:
        renderer = UPGRADE.upgrade_systemd.render_reconcile_unit_bundle
        with mock.patch.object(
            UPGRADE.upgrade_systemd,
            "render_reconcile_unit_bundle",
            wraps=renderer,
        ) as render:
            _state, _candidate, _transaction, _document, plan = self._prepare()

        candidate_backend = (
            self.root / "candidate-repository" / "services" / "backend"
        )
        render.assert_called_once()
        self.assertEqual(
            render.call_args.args[0],
            candidate_backend / "systemd",
        )
        self.assertEqual(
            plan["finalize"]["reconcile_bindings"]["reconciler"],
            str(
                candidate_backend
                / "scripts"
                / "reconcile_compose_deployment.py"
            ),
        )

    def test_plan_rejects_finalize_reconciler_rebinding(self) -> None:
        _state, _candidate, _transaction, plan_document, _plan = self._prepare()
        rebound = deepcopy(plan_document)
        rebound["plan"]["finalize"]["reconcile_bindings"]["reconciler"] = str(
            self.root
            / "source-repository"
            / "services"
            / "backend"
            / "scripts"
            / "reconcile_compose_deployment.py"
        )

        with self.assertRaisesRegex(
            UPGRADE.UpgradeError,
            "REVIEWER_UPGRADE_STATE_INVALID",
        ):
            UPGRADE._validate_plan(rebound)

    def test_plan_binds_backup_without_plan_digest_circularity(self) -> None:
        state, _candidate, _transaction, plan_document, plan = self._prepare()
        self.assertNotIn("plan_digest", plan["backup"])
        bindings = UPGRADE._backup_bindings(plan_document, plan)
        self.assertEqual(bindings.plan_digest, plan_document["plan_digest"])
        self.assertEqual(bindings.operation_id, plan["operation_id"])
        self.assertEqual(bindings.source_state_directory, state)
        self.assertEqual(
            bindings.backend_container_id,
            plan["backup"]["backend"]["container_id"],
        )

    def test_finalize_bindings_reload_sidecars_without_template_access(self) -> None:
        state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        sealed = Path(plan["sealed_state_directory"])
        shutil.copytree(state, sealed)
        rebound = {
            **plan["finalize"]["lock_file_binding"],
            "inode": plan["finalize"]["lock_file_binding"]["inode"] + 41,
        }
        holder = {"descriptor": 91, "expected_binding": rebound}
        with mock.patch.object(
            UPGRADE.upgrade_systemd,
            "render_reconcile_unit_bundle",
            side_effect=AssertionError("templates re-read during resume"),
        ), mock.patch.object(
            UPGRADE,
            "_processing_lock_callbacks",
            return_value=mock.Mock(),
        ) as processing_callbacks:
            bindings = UPGRADE._finalize_bindings(
                transaction,
                plan,
                plan_document["plan_digest"],
                gate,
                holder,
            )
        old, target = UPGRADE.unit_artifacts.load_unit_bundle_artifacts(
            transaction,
            plan["unit_artifacts"],
        )
        self.assertEqual(bindings.old_units, old)
        self.assertEqual(bindings.target_units, target)
        self.assertEqual(processing_callbacks.call_args.args[3], rebound)

    def test_backup_plan_projects_only_file_identity_from_full_binding(self) -> None:
        state, _candidate = self._fixture()
        desired, manifest, compose = UPGRADE.reconciler._load_bound_state(state)
        compose_document = UPGRADE.reconciler._parse_json(
            compose.read_bytes(),
            "REVIEWER_UPGRADE_BACKUP_INVALID",
        )
        expanded = deepcopy(manifest)
        for key in ("config", "secret"):
            path = Path(expanded[key]["path"])
            metadata = path.lstat()
            expanded[key] = {
                **expanded[key],
                "ancestry": [
                    {
                        "device": state.parent.lstat().st_dev,
                        "inode": state.parent.lstat().st_ino,
                        "mode": stat.S_IMODE(state.parent.lstat().st_mode),
                        "path": str(state.parent),
                        "uid": state.parent.lstat().st_uid,
                    }
                ],
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
            }
        payload = UPGRADE._backup_plan_payload(
            "reviewer-full-binding",
            state,
            expanded,
            compose_document,
        )
        for key in ("config", "secret"):
            self.assertEqual(
                set(payload[key]),
                {"digest", "mode", "path", "size", "uid"},
            )
        self.assertEqual(desired["desired"], "running")

    def test_candidate_relocation_accepts_production_compose_without_builds(
        self,
    ) -> None:
        state, candidate = self._fixture()
        source_document, candidate_document = self._candidate_documents(
            state,
            candidate,
        )
        old_ref, new_ref, source_root, candidate_root = (
            UPGRADE._candidate_relocation(
                source_document,
                candidate_document,
            )
        )
        self.assertEqual(old_ref, "tacua-reviewer-web:old")
        self.assertEqual(new_ref, "tacua-reviewer-web:candidate")
        self.assertEqual(source_root, self.root / "source-repository")
        self.assertEqual(candidate_root, self.root / "candidate-repository")

    def test_candidate_relocation_accepts_exact_local_build_contexts(
        self,
    ) -> None:
        state, candidate = self._fixture()
        source_document, candidate_document = self._candidate_documents(
            state,
            candidate,
        )
        for service in ("backend", "reviewer"):
            source_document["services"][service]["build"] = {
                "context": str(self.root / "source-repository"),
                "dockerfile": f"docker/{service}.Dockerfile",
            }
            candidate_document["services"][service]["build"] = {
                "context": str(self.root / "candidate-repository"),
                "dockerfile": f"docker/{service}.Dockerfile",
            }
        _old, _new, source_root, candidate_root = (
            UPGRADE._candidate_relocation(
                source_document,
                candidate_document,
            )
        )
        self.assertEqual(source_root, self.root / "source-repository")
        self.assertEqual(candidate_root, self.root / "candidate-repository")

    def test_candidate_relocation_rejects_incomplete_build_relocation(
        self,
    ) -> None:
        state, candidate = self._fixture()
        source_document, candidate_document = self._candidate_documents(
            state,
            candidate,
        )
        source_document["services"]["backend"]["build"] = {
            "context": str(self.root / "source-repository"),
            "dockerfile": "docker/backend.Dockerfile",
        }
        cases = []
        missing = deepcopy(candidate_document)
        cases.append(missing)
        wrong = deepcopy(candidate_document)
        wrong["services"]["backend"]["build"] = {
            "context": str(self.root / "source-repository"),
            "dockerfile": "docker/backend.Dockerfile",
        }
        cases.append(wrong)
        null_build = deepcopy(candidate_document)
        null_build["services"]["backend"]["build"] = None
        cases.append(null_build)
        for selected in cases:
            with self.subTest(selected=selected), self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "REVIEWER_UPGRADE_CANDIDATE_INVALID",
            ):
                UPGRADE._candidate_relocation(
                    source_document,
                    selected,
                )

    def test_candidate_relocation_rejects_wrong_ingress_authority(self) -> None:
        state, candidate = self._fixture()
        source_document, candidate_document = self._candidate_documents(
            state,
            candidate,
        )
        cases = []
        wrong_suffix = deepcopy(candidate_document)
        wrong_suffix["configs"]["tacua_loopback_ingress"]["file"] = str(
            self.root / "candidate-repository" / "wrong" / "haproxy.cfg"
        )
        cases.append(wrong_suffix)
        same_root = deepcopy(candidate_document)
        same_root["configs"]["tacua_loopback_ingress"]["file"] = str(
            self.root / "source-repository" / UPGRADE.INGRESS_CONFIG_SUFFIX
        )
        cases.append(same_root)
        unsafe_root = deepcopy(candidate_document)
        unsafe_root["configs"]["tacua_loopback_ingress"]["file"] = str(
            self.root
            / "candidate repository"
            / UPGRADE.INGRESS_CONFIG_SUFFIX
        )
        cases.append(unsafe_root)
        for selected in cases:
            with self.subTest(selected=selected), self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "REVIEWER_UPGRADE_CANDIDATE_INVALID",
            ):
                UPGRADE._candidate_relocation(
                    source_document,
                    selected,
                )

    def test_prepare_rejects_any_non_authority_compose_change(self) -> None:
        state, candidate = self._fixture(
            candidate_change=("environment", {"UNEXPECTED": "1"})
        )
        desired, manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        deployment = {
            "containers": manifest["containers"],
            "resources": manifest["resources"],
        }
        with mock.patch.object(
            UPGRADE,
            "_prepare_live_preconditions",
            return_value=deployment,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_host_lock",
            return_value=91,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_release_lock",
        ):
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "REVIEWER_UPGRADE_CANDIDATE_INVALID",
            ):
                UPGRADE.prepare(
                    state,
                    candidate,
                    **self._upgrade_abi(state),
                    runner=self._runner,
                    operation_id="reviewer-invalid-candidate",
                )
        upgrades = self.root / UPGRADE.UPGRADES_DIRECTORY
        self.assertIsNone(UPGRADE._load_active(upgrades, optional=True))
        self.assertEqual(desired["desired"], "running")

    def test_prepare_rejects_prepared_reviewer_tag_rebound_before_publication(
        self,
    ) -> None:
        state, candidate = self._fixture()
        _desired, manifest, _compose = UPGRADE.reconciler._load_bound_state(
            state
        )
        deployment = {
            "containers": manifest["containers"],
            "resources": manifest["resources"],
        }
        with mock.patch.object(
            UPGRADE,
            "_prepare_live_preconditions",
            return_value=deployment,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_host_lock",
            return_value=91,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_release_lock",
        ), mock.patch.object(
            UPGRADE,
            "_create_transaction",
        ) as create_transaction:
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "REVIEWER_UPGRADE_CANDIDATE_REBOUND",
            ):
                UPGRADE.prepare(
                    state,
                    candidate,
                    **self._upgrade_abi(state),
                    runner=self._runner,
                    operation_id="reviewer-rebound-candidate",
                    expected_candidate_image_ref=(
                        "tacua-reviewer-web:candidate"
                    ),
                    expected_candidate_image_id=OLD_IMAGE_ID,
                )
        create_transaction.assert_not_called()
        self.assertIsNone(
            UPGRADE._load_active(
                self.root / UPGRADE.UPGRADES_DIRECTORY,
                optional=True,
            )
        )

    def test_resume_drives_prepared_through_gate_and_maintenance(self) -> None:
        state, _candidate, transaction, plan_document, plan = self._prepare(
            drive_gate=False
        )
        runner = mock.Mock(side_effect=AssertionError("Docker runner called"))

        def set_maintenance(
            selected_state,
            runner,
            *,
            require_running,
            lock_descriptor,
        ):
            self.assertEqual(selected_state, state)
            self.assertIs(runner, runner_mock)
            self.assertTrue(require_running)
            self.assertEqual(lock_descriptor, 91)
            self._set_maintenance(state)
            return {"code": "RECONCILE_MAINTENANCE", "status": "maintenance"}

        runner_mock = runner
        with mock.patch.object(
            UPGRADE.reconciler,
            "_host_lock",
            return_value=91,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_release_lock",
        ), mock.patch.object(
            UPGRADE.reconciler,
            "set_maintenance",
            side_effect=set_maintenance,
        ) as maintenance, mock.patch.object(
            UPGRADE.reconciler,
            "reconcile",
        ) as reconcile, mock.patch.object(
            UPGRADE,
            "_prove_maintenance",
            side_effect=self._fake_maintenance_proof,
        ):
            result = UPGRADE.resume(
                self.root,
                runner=runner,
                _defer_backup_for_test=True,
                _skip_processing_lock_binding_for_test=True,
            )

        self.assertEqual(result["status"], "waiting_backup")
        self.assertEqual(result["phase"], UPGRADE.MAINTENANCE)
        maintenance.assert_called_once()
        reconcile.assert_not_called()
        runner.assert_not_called()
        progress = self._progress(transaction, plan_document)
        self.assertEqual(progress["phase"], UPGRADE.MAINTENANCE)
        gate = progress["details"]["processing_gate"]
        self.assertEqual(gate["inhibitor"]["plan_digest"], plan_document["plan_digest"])
        UPGRADE._validate_processing_gate(
            gate,
            plan,
            plan_document["plan_digest"],
            require_live=True,
        )

    def test_prepare_requires_a_settled_running_source(self) -> None:
        state, candidate = self._fixture(desired_state="maintenance")
        with mock.patch.object(
            UPGRADE.reconciler,
            "_host_lock",
            return_value=91,
        ), mock.patch.object(UPGRADE.reconciler, "_release_lock"):
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "REVIEWER_UPGRADE_RUNNING_REQUIRED",
            ):
                UPGRADE.prepare(
                    state,
                    candidate,
                    **self._upgrade_abi(state),
                    runner=self._runner,
                    operation_id="reviewer-maintenance-source",
                )
        self.assertIsNone(
            UPGRADE._load_active(
                self.root / UPGRADE.UPGRADES_DIRECTORY,
                optional=True,
            )
        )

    def test_existing_empty_processing_directory_is_never_adopted(self) -> None:
        state, _candidate = self._fixture()
        desired, manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        deployment = {
            "containers": manifest["containers"],
            "resources": manifest["resources"],
        }
        operation = (
            Path(manifest["operation_directory"])
            / "tacua-compose-processing-reconcile-test"
        )
        operation.mkdir(mode=0o700)
        with mock.patch.object(
            UPGRADE,
            "_prepare_live_preconditions",
            return_value=deployment,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_host_lock",
            return_value=91,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_release_lock",
        ), mock.patch.object(
            UPGRADE,
            "_bound_lock_file",
            return_value=self._test_lock_binding(state),
        ):
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "REVIEWER_UPGRADE_INHIBITOR_AMBIGUOUS",
            ):
                UPGRADE.prepare(
                    state,
                    self.root / "candidate-compose.json",
                    **self._upgrade_abi(state),
                    runner=self._runner,
                    operation_id="reviewer-empty-operation",
                )
        self.assertEqual(desired["desired"], "running")
        self.assertEqual(list(operation.iterdir()), [])
        active = UPGRADE._load_active(
            self.root / UPGRADE.UPGRADES_DIRECTORY,
        )
        assert active is not None
        _transaction, _document, _plan, progress = UPGRADE._load_transaction(
            self.root / UPGRADE.UPGRADES_DIRECTORY,
            active,
        )
        self.assertEqual(progress["phase"], UPGRADE.QUIESCING)
        self.assertEqual(progress["details"]["gate_state"], UPGRADE.GATE_PENDING)

    def test_bound_gate_crash_is_repaired_without_rebinding(self) -> None:
        (
            _state,
            transaction,
            plan_document,
            plan,
            manifest,
            operation,
            binding,
            progress,
        ) = self._prepare_bound_gate()

        repaired, gate = UPGRADE._drive_processing_gate(
            transaction,
            plan_document,
            plan,
            progress,
            manifest,
        )
        self.assertEqual(
            repaired["details"]["gate_state"],
            UPGRADE.GATE_INHIBITOR_READY,
        )
        self.assertEqual(gate["operation_directory_binding"], binding)
        self.assertEqual(UPGRADE._operation_directory_binding(operation), binding)
        inhibitor_path = operation / UPGRADE.INHIBITOR_FILE
        self.assertTrue(inhibitor_path.is_file())

        repeated, repeated_gate = UPGRADE._drive_processing_gate(
            transaction,
            plan_document,
            plan,
            repaired,
            manifest,
        )
        self.assertEqual(repeated, repaired)
        self.assertEqual(repeated_gate, gate)
        self.assertEqual(UPGRADE._operation_directory_binding(operation), binding)

    def test_canonical_inhibitor_staging_crash_is_discarded_and_retried(self) -> None:
        (
            _state,
            transaction,
            plan_document,
            plan,
            manifest,
            operation,
            _binding,
            progress,
        ) = self._prepare_bound_gate()
        expected = UPGRADE.journal.canonical_json(
            UPGRADE._inhibitor_document(
                plan["project"],
                plan_document["plan_digest"],
            )
        )
        staging = operation / UPGRADE.INHIBITOR_STAGING_FILE
        UPGRADE._write_private_staging(staging, expected)

        repaired, _gate = UPGRADE._drive_processing_gate(
            transaction,
            plan_document,
            plan,
            progress,
            manifest,
        )
        self.assertEqual(repaired["details"]["gate_state"], UPGRADE.GATE_INHIBITOR_READY)
        self.assertFalse(staging.exists())
        self.assertEqual((operation / UPGRADE.INHIBITOR_FILE).read_bytes(), expected)

    def test_committed_inhibitor_hardlink_crash_unlinks_only_staging(self) -> None:
        (
            _state,
            transaction,
            plan_document,
            plan,
            manifest,
            operation,
            _binding,
            progress,
        ) = self._prepare_bound_gate()
        expected = UPGRADE.journal.canonical_json(
            UPGRADE._inhibitor_document(
                plan["project"],
                plan_document["plan_digest"],
            )
        )
        staging = operation / UPGRADE.INHIBITOR_STAGING_FILE
        final = operation / UPGRADE.INHIBITOR_FILE
        UPGRADE._write_private_staging(staging, expected)
        os.link(staging, final)
        committed_inode = final.lstat().st_ino

        repaired, _gate = UPGRADE._drive_processing_gate(
            transaction,
            plan_document,
            plan,
            progress,
            manifest,
        )
        self.assertEqual(repaired["details"]["gate_state"], UPGRADE.GATE_INHIBITOR_READY)
        self.assertFalse(staging.exists())
        self.assertEqual(final.lstat().st_ino, committed_inode)
        self.assertEqual(final.lstat().st_nlink, 1)

    def test_partial_inhibitor_staging_is_rejected_as_ambiguous(self) -> None:
        (
            _state,
            transaction,
            plan_document,
            plan,
            manifest,
            operation,
            _binding,
            progress,
        ) = self._prepare_bound_gate()
        staging = operation / UPGRADE.INHIBITOR_STAGING_FILE
        staging.write_bytes(b"partial")
        staging.chmod(0o600)

        with self.assertRaisesRegex(
            UPGRADE.UpgradeError,
            "REVIEWER_UPGRADE_INHIBITOR_INVALID",
        ):
            UPGRADE._drive_processing_gate(
                transaction,
                plan_document,
                plan,
                progress,
                manifest,
            )
        self.assertTrue(staging.is_file())
        self.assertFalse((operation / UPGRADE.INHIBITOR_FILE).exists())

    def test_pending_maintenance_marker_is_reconciled_under_borrowed_lock(self) -> None:
        state, _candidate, transaction, plan_document, _plan = self._prepare()
        desired, _manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        UPGRADE.reconciler._write_maintenance_transition(state, desired)
        runner = mock.Mock(side_effect=AssertionError("Docker runner called"))

        def finish_transition(
            selected_state,
            runner,
            *,
            lock_descriptor,
        ):
            self.assertEqual(selected_state, state)
            self.assertIs(runner, runner_mock)
            self.assertEqual(lock_descriptor, 91)
            self._set_maintenance(state)
            UPGRADE.reconciler._remove_activation(state)
            return {"code": "RECONCILE_MAINTENANCE", "status": "maintenance"}

        runner_mock = runner
        with mock.patch.object(
            UPGRADE.reconciler,
            "_host_lock",
            return_value=91,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_release_lock",
        ), mock.patch.object(
            UPGRADE.reconciler,
            "set_maintenance",
        ) as maintenance, mock.patch.object(
            UPGRADE.reconciler,
            "reconcile",
            side_effect=finish_transition,
        ) as reconcile, mock.patch.object(
            UPGRADE,
            "_prove_maintenance",
            side_effect=self._fake_maintenance_proof,
        ):
            result = UPGRADE.resume(
                self.root,
                runner=runner,
                _defer_backup_for_test=True,
                _skip_processing_lock_binding_for_test=True,
            )

        self.assertEqual(result["status"], "waiting_backup")
        maintenance.assert_not_called()
        reconcile.assert_called_once()
        runner.assert_not_called()
        self.assertEqual(
            self._progress(transaction, plan_document)["phase"],
            UPGRADE.MAINTENANCE,
        )

    def test_settled_maintenance_is_checkpointed_and_resume_is_idempotent(self) -> None:
        state, _candidate, transaction, plan_document, _plan = self._prepare()
        self._set_maintenance(state)
        runner = mock.Mock(side_effect=AssertionError("Docker runner called"))
        with mock.patch.object(
            UPGRADE.reconciler,
            "_host_lock",
            return_value=91,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_release_lock",
        ), mock.patch.object(
            UPGRADE.reconciler,
            "set_maintenance",
        ) as maintenance, mock.patch.object(
            UPGRADE.reconciler,
            "reconcile",
        ) as reconcile, mock.patch.object(
            UPGRADE,
            "_prove_maintenance",
            side_effect=self._fake_maintenance_proof,
        ) as prove:
            first = UPGRADE.resume(
                self.root,
                runner=runner,
                _defer_backup_for_test=True,
                _skip_processing_lock_binding_for_test=True,
            )
            checkpoint = self._progress(transaction, plan_document)
            second = UPGRADE.resume(
                self.root,
                runner=runner,
                _defer_backup_for_test=True,
                _skip_processing_lock_binding_for_test=True,
            )
            repeated = self._progress(transaction, plan_document)

        self.assertEqual(first, second)
        self.assertEqual(first["status"], "waiting_backup")
        self.assertEqual(checkpoint, repeated)
        maintenance.assert_not_called()
        reconcile.assert_not_called()
        self.assertEqual(prove.call_count, 2)
        runner.assert_not_called()

    def test_maintenance_proof_requires_private_runtime_health(self) -> None:
        state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        self._set_maintenance(state)
        desired, manifest, compose = UPGRADE.reconciler._load_bound_state(state)
        deployment = {
            "containers": manifest["containers"],
            "resources": manifest["resources"],
        }
        runner = mock.Mock()
        with mock.patch.object(
            UPGRADE.reconciler,
            "_require_empty_tailnet_preactivation",
        ) as empty_serve, mock.patch.object(
            UPGRADE.reconciler,
            "_daemon_projection",
            return_value=manifest["daemon"],
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_inspect_deployment",
            return_value=(deployment, True),
        ) as inspect, mock.patch.object(
            UPGRADE.reconciler,
            "_smoke",
        ) as smoke:
            details = UPGRADE._prove_maintenance(
                plan,
                plan_document["plan_digest"],
                gate,
                desired,
                manifest,
                compose,
                runner,
            )

        empty_serve.assert_called_once_with(manifest, compose, runner)
        inspect.assert_called_once_with(manifest, compose, runner)
        smoke.assert_called_once_with(manifest, public=False)
        self.assertEqual(details["processing_gate"], gate)
        self.assertEqual(
            details["deployment_digest"],
            UPGRADE.reconciler._digest(UPGRADE.reconciler._canonical(deployment)),
        )

    def test_backup_failure_leaves_durable_backing_up_checkpoint(self) -> None:
        (
            _state,
            transaction,
            plan_document,
            plan,
            progress,
            desired,
            manifest,
            compose,
        ) = self._checkpoint_maintenance()
        gate = progress["details"]["processing_gate"]
        with mock.patch.object(
            UPGRADE,
            "_validate_maintenance_runtime",
        ), mock.patch.object(
            UPGRADE.backup,
            "run_backup_attempt",
            side_effect=UPGRADE.backup.BackupError(
                "REVIEWER_UPGRADE_BACKUP_FAILED"
            ),
        ) as attempt:
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "REVIEWER_UPGRADE_BACKUP_FAILED",
            ):
                UPGRADE._drive_backup(
                    transaction,
                    plan_document,
                    plan,
                    progress,
                    desired,
                    manifest,
                    compose,
                    mock.Mock(),
                    mock.Mock(),
                )

        attempt.assert_called_once()
        durable = self._progress(transaction, plan_document)
        self.assertEqual(durable["phase"], UPGRADE.BACKING_UP)
        self.assertEqual(durable["details"], {"processing_gate": gate})

    def test_backing_up_resumes_after_receipt_checkpoint_crash(self) -> None:
        (
            _state,
            transaction,
            plan_document,
            plan,
            progress,
            desired,
            manifest,
            compose,
        ) = self._checkpoint_maintenance()
        receipt = self._backup_receipt(plan_document, plan)
        original_checkpoint = UPGRADE._checkpoint

        def crash_before_receipt_checkpoint(
            selected_transaction,
            selected_plan,
            phase,
            details,
        ):
            if phase == UPGRADE.BACKUP_READY:
                raise UPGRADE.UpgradeError("SYNTHETIC_CRASH")
            return original_checkpoint(
                selected_transaction,
                selected_plan,
                phase,
                details,
            )

        with mock.patch.object(
            UPGRADE,
            "_validate_maintenance_runtime",
        ), mock.patch.object(
            UPGRADE.backup,
            "run_backup_attempt",
            return_value=receipt,
        ) as attempt, mock.patch.object(
            UPGRADE,
            "_checkpoint",
            side_effect=crash_before_receipt_checkpoint,
        ):
            with self.assertRaisesRegex(UPGRADE.UpgradeError, "SYNTHETIC_CRASH"):
                UPGRADE._drive_backup(
                    transaction,
                    plan_document,
                    plan,
                    progress,
                    desired,
                    manifest,
                    compose,
                    mock.Mock(),
                    mock.Mock(),
                )

        backing_up = self._progress(transaction, plan_document)
        self.assertEqual(backing_up["phase"], UPGRADE.BACKING_UP)
        with mock.patch.object(
            UPGRADE,
            "_validate_maintenance_runtime",
        ), mock.patch.object(
            UPGRADE.backup,
            "run_backup_attempt",
            return_value=receipt,
        ) as resumed:
            backup_ready = UPGRADE._drive_backup(
                transaction,
                plan_document,
                plan,
                backing_up,
                desired,
                manifest,
                compose,
                mock.Mock(),
                mock.Mock(),
            )

        self.assertEqual(attempt.call_count, 1)
        self.assertEqual(resumed.call_count, 1)
        self.assertEqual(backup_ready["phase"], UPGRADE.BACKUP_READY)
        self.assertEqual(backup_ready["details"]["backup_receipt"], receipt)
        self.assertEqual(
            backup_ready["details"]["processing_gate"],
            progress["details"]["processing_gate"],
        )

    def test_backup_ready_resume_reverifies_exact_receipt_idempotently(self) -> None:
        (
            _state,
            transaction,
            plan_document,
            plan,
            progress,
            desired,
            manifest,
            compose,
        ) = self._checkpoint_maintenance()
        receipt = self._backup_receipt(plan_document, plan)
        backup_ready = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.BACKUP_READY,
            {
                "backup_receipt": receipt,
                "processing_gate": progress["details"]["processing_gate"],
            },
        )
        with mock.patch.object(
            UPGRADE,
            "_validate_maintenance_runtime",
        ), mock.patch.object(
            UPGRADE.backup,
            "run_backup_attempt",
            return_value=receipt,
        ) as attempt:
            repeated = UPGRADE._drive_backup(
                transaction,
                plan_document,
                plan,
                backup_ready,
                desired,
                manifest,
                compose,
                mock.Mock(),
                mock.Mock(),
            )

        attempt.assert_called_once()
        self.assertEqual(repeated, backup_ready)
        self.assertEqual(self._progress(transaction, plan_document), backup_ready)

    def test_resume_recovers_backing_up_to_durable_backup_ready(self) -> None:
        (
            _state,
            transaction,
            plan_document,
            plan,
            progress,
            _desired,
            _manifest,
            _compose,
        ) = self._checkpoint_maintenance()
        receipt = self._backup_receipt(plan_document, plan)
        backing_up = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.BACKING_UP,
            {"processing_gate": progress["details"]["processing_gate"]},
        )
        self.assertEqual(backing_up["phase"], UPGRADE.BACKING_UP)
        runner = mock.Mock()
        production_backup = mock.Mock()
        with mock.patch.object(
            UPGRADE.reconciler,
            "_host_lock",
            return_value=91,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_release_lock",
        ), mock.patch.object(
            UPGRADE,
            "_validate_maintenance_runtime",
        ), mock.patch.object(
            UPGRADE.backup_docker,
            "create_docker_backup_runner",
            return_value=production_backup,
        ) as factory, mock.patch.object(
            UPGRADE.backup,
            "run_backup_attempt",
            return_value=receipt,
        ) as attempt, mock.patch.object(
            UPGRADE,
            "_image_id",
            return_value=CANDIDATE_IMAGE_ID,
        ), mock.patch.object(
            UPGRADE,
            "_classify_deployment",
            side_effect=UPGRADE.UpgradeError("STOP_AFTER_BACKUP"),
        ):
            with self.assertRaisesRegex(UPGRADE.UpgradeError, "STOP_AFTER_BACKUP"):
                UPGRADE.resume(
                    self.root,
                    runner=runner,
                    _skip_processing_lock_binding_for_test=True,
                )

        attempt.assert_called_once()
        factory.assert_called_once_with(
            transaction,
            UPGRADE._backup_bindings(plan_document, plan),
            mock.ANY,
            mock.ANY,
            runner,
        )
        self.assertIs(attempt.call_args.args[2], production_backup)
        durable = self._progress(transaction, plan_document)
        self.assertEqual(durable["phase"], UPGRADE.BACKUP_READY)
        self.assertEqual(durable["details"]["backup_receipt"], receipt)
        self.assertEqual(
            durable["details"]["processing_gate"],
            progress["details"]["processing_gate"],
        )

    def test_malformed_processing_gate_has_stable_error(self) -> None:
        _state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        gate["operation_directory_binding"] = None
        with self.assertRaisesRegex(
            UPGRADE.UpgradeError,
            "REVIEWER_UPGRADE_INHIBITOR_INVALID",
        ):
            UPGRADE._validate_processing_gate(
                gate,
                plan,
                plan_document["plan_digest"],
            )

    def test_activation_checkpoint_crash_retries_set_running_before_unlink(self) -> None:
        _state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        target_digests = {
            name: "sha256:" + str(index + 1) * 64
            for index, name in enumerate(UPGRADE.upgrade_systemd.UNIT_NAMES)
        }
        promotion = self._finalize_receipt(
            "promote_target_maintenance",
            "maintenance_ready",
            {"target_unit_digests": target_digests},
        )
        activation = self._finalize_receipt(
            "activate_target",
            "running_gate_held",
            {"inhibitor_digest": gate["inhibitor"]["inhibitor_digest"]},
        )
        removal = self._finalize_receipt(
            "remove_processing_gate",
            "gate_absent",
            {"inhibitor_digest": gate["inhibitor"]["inhibitor_digest"]},
        )
        scheduled = self._finalize_receipt(
            "prove_later_scheduled_reconcile",
            "scheduled_reconcile_proven",
            {"invocation_id": "a" * 32},
        )
        pending = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.ACTIVATING,
            UPGRADE._activating_details(
                gate,
                promotion,
                UPGRADE.ACTIVATION_PENDING,
            ),
        )
        fake_bindings = mock.Mock()
        fake_bindings.target_units.digests.return_value = target_digests
        activate = mock.Mock(return_value=(91, activation))
        real_checkpoint = UPGRADE._checkpoint

        def crash_after_activation(
            selected_transaction,
            selected_plan,
            phase,
            details,
        ):
            if (
                phase == UPGRADE.ACTIVATING
                and details.get("substage")
                == UPGRADE.ACTIVATION_RUNNING_GATE_HELD
            ):
                raise UPGRADE.UpgradeError("CRASH_AFTER_ACTIVATION")
            return real_checkpoint(
                selected_transaction,
                selected_plan,
                phase,
                details,
            )

        with mock.patch.object(
            UPGRADE,
            "_finalize_bindings",
            return_value=fake_bindings,
        ), mock.patch.object(
            UPGRADE.finalize,
            "activate_target",
            activate,
        ), mock.patch.object(
            UPGRADE,
            "_checkpoint",
            side_effect=crash_after_activation,
        ):
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "CRASH_AFTER_ACTIVATION",
            ):
                UPGRADE._drive_finalization(
                    transaction,
                    plan_document,
                    plan,
                    pending,
                    gate,
                    mock.Mock(),
                    {"descriptor": 91},
                )
        durable = self._progress(transaction, plan_document)
        self.assertEqual(durable["phase"], UPGRADE.ACTIVATING)
        self.assertEqual(
            durable["details"]["substage"],
            UPGRADE.ACTIVATION_PENDING,
        )
        with mock.patch.object(
            UPGRADE,
            "_finalize_bindings",
            return_value=fake_bindings,
        ), mock.patch.object(
            UPGRADE.finalize,
            "activate_target",
            activate,
        ), mock.patch.object(
            UPGRADE.finalize,
            "remove_processing_gate",
            return_value=(91, removal),
        ) as remove, mock.patch.object(
            UPGRADE.finalize,
            "prove_later_scheduled_reconcile",
            return_value=(91, scheduled),
        ) as prove:
            complete = UPGRADE._drive_finalization(
                transaction,
                plan_document,
                plan,
                durable,
                gate,
                mock.Mock(),
                {"descriptor": 91},
            )
        self.assertEqual(complete["phase"], UPGRADE.COMPLETE)
        self.assertEqual(activate.call_count, 2)
        remove.assert_called_once()
        prove.assert_called_once()

    def test_gate_unlink_checkpoint_crash_retries_idempotent_removal(self) -> None:
        _state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        target_digests = {
            name: "sha256:" + str(index + 4) * 64
            for index, name in enumerate(UPGRADE.upgrade_systemd.UNIT_NAMES)
        }
        promotion = self._finalize_receipt(
            "promote_target_maintenance",
            "maintenance_ready",
            {"target_unit_digests": target_digests},
        )
        activation = self._finalize_receipt(
            "activate_target",
            "running_gate_held",
            {"inhibitor_digest": gate["inhibitor"]["inhibitor_digest"]},
        )
        removal = self._finalize_receipt(
            "remove_processing_gate",
            "gate_absent",
            {"inhibitor_digest": gate["inhibitor"]["inhibitor_digest"]},
        )
        scheduled = self._finalize_receipt(
            "prove_later_scheduled_reconcile",
            "scheduled_reconcile_proven",
            {"invocation_id": "b" * 32},
        )
        running = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.ACTIVATING,
            UPGRADE._activating_details(
                gate,
                promotion,
                UPGRADE.ACTIVATION_RUNNING_GATE_HELD,
                activation_receipt=activation,
            ),
        )
        fake_bindings = mock.Mock()
        fake_bindings.target_units.digests.return_value = target_digests
        remove = mock.Mock(return_value=(91, removal))
        real_checkpoint = UPGRADE._checkpoint

        def crash_after_unlink(
            selected_transaction,
            selected_plan,
            phase,
            details,
        ):
            if (
                phase == UPGRADE.ACTIVATING
                and details.get("substage") == UPGRADE.ACTIVATION_GATE_ABSENT
            ):
                raise UPGRADE.UpgradeError("CRASH_AFTER_GATE_UNLINK")
            return real_checkpoint(
                selected_transaction,
                selected_plan,
                phase,
                details,
            )

        with mock.patch.object(
            UPGRADE,
            "_finalize_bindings",
            return_value=fake_bindings,
        ), mock.patch.object(
            UPGRADE.finalize,
            "remove_processing_gate",
            remove,
        ), mock.patch.object(
            UPGRADE,
            "_checkpoint",
            side_effect=crash_after_unlink,
        ):
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "CRASH_AFTER_GATE_UNLINK",
            ):
                UPGRADE._drive_finalization(
                    transaction,
                    plan_document,
                    plan,
                    running,
                    gate,
                    mock.Mock(),
                    {"descriptor": 91},
                )
        durable = self._progress(transaction, plan_document)
        self.assertEqual(
            durable["details"]["substage"],
            UPGRADE.ACTIVATION_RUNNING_GATE_HELD,
        )
        with mock.patch.object(
            UPGRADE,
            "_finalize_bindings",
            return_value=fake_bindings,
        ), mock.patch.object(
            UPGRADE.finalize,
            "remove_processing_gate",
            remove,
        ), mock.patch.object(
            UPGRADE.finalize,
            "prove_later_scheduled_reconcile",
            return_value=(91, scheduled),
        ):
            complete = UPGRADE._drive_finalization(
                transaction,
                plan_document,
                plan,
                durable,
                gate,
                mock.Mock(),
                {"descriptor": 91},
            )
        self.assertEqual(complete["phase"], UPGRADE.COMPLETE)
        self.assertEqual(remove.call_count, 2)

    def test_resume_replaces_without_force_then_seals_to_stable_path(self) -> None:
        state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        receipt = self._backup_receipt(plan_document, plan)
        self._set_maintenance(state)
        UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.BACKUP_READY,
            {
                "backup_receipt": receipt,
                "processing_gate": gate,
            },
        )
        old = {
            "classification": UPGRADE.OLD,
            "deployment": {},
            "deployment_digest": "sha256:" + "7" * 64,
            "health": {service: True for service in UPGRADE.reconciler.SERVICES},
        }
        deployment = {
            "containers": {
                "backend": {"id": BACKEND_ID},
                "ingress": {"id": INGRESS_ID},
                "reviewer": {
                    "id": CANDIDATE_REVIEWER_ID,
                    "image_id": CANDIDATE_IMAGE_ID,
                },
            },
            "resources": {},
        }
        candidate_state = {
            "classification": UPGRADE.CANDIDATE,
            "deployment": deployment,
            "deployment_digest": UPGRADE.reconciler._digest(
                UPGRADE.reconciler._canonical(deployment)
            ),
            "health": {service: True for service in UPGRADE.reconciler.SERVICES},
        }
        compose_calls: list[list[str]] = []

        def runner(argv, *, timeout):
            compose_calls.append(list(argv))
            return b""

        def fake_seal(
            args,
            runner,
            *,
            lock_descriptor,
            upgrade_inhibitor,
            expected_repository_root,
        ):
            self.assertEqual(lock_descriptor, 91)
            self.assertEqual(
                expected_repository_root,
                self.root / "candidate-repository",
            )
            self.assertEqual(
                upgrade_inhibitor["plan_digest"],
                plan_document["plan_digest"],
            )
            args.state_directory.mkdir(mode=0o700)
            return {"code": "RECONCILE_SEALED", "status": "maintenance"}

        with mock.patch.object(
            UPGRADE,
            "_candidate_relocation",
            wraps=UPGRADE._candidate_relocation,
        ) as relocation, mock.patch.object(
            UPGRADE.reconciler,
            "_host_lock",
            return_value=91,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_release_lock",
        ), mock.patch.object(
            UPGRADE,
            "_validate_maintenance_runtime",
        ), mock.patch.object(
            UPGRADE,
            "_image_id",
            return_value=CANDIDATE_IMAGE_ID,
        ), mock.patch.object(
            UPGRADE,
            "_classify_deployment",
            side_effect=[old, old, candidate_state],
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_smoke",
        ), mock.patch.object(
            UPGRADE.reconciler,
            "seal",
            side_effect=fake_seal,
        ) as seal, mock.patch.object(
            UPGRADE,
            "_sealed_state_valid",
            return_value=True,
        ), mock.patch.object(
            UPGRADE.backup,
            "run_backup_attempt",
            return_value=receipt,
        ):
            result = UPGRADE.resume(
                self.root,
                runner=runner,
                backup_runner=mock.Mock(),
                _defer_finalization_for_test=True,
                _skip_processing_lock_binding_for_test=True,
            )

        self.assertEqual(result["phase"], UPGRADE.SEALED_MAINTENANCE)
        relocation.assert_called_once()
        seal.assert_called_once()
        self.assertEqual(len(compose_calls), 1)
        command = compose_calls[0]
        self.assertEqual(command[-7:], [
            "up",
            "-d",
            "--no-deps",
            "--no-build",
            "--pull",
            "never",
            "reviewer",
        ])
        self.assertNotIn("--force-recreate", command)
        self.assertTrue(Path(plan["sealed_state_directory"]).is_dir())
        self.assertFalse((transaction / "seal-attempt-1").exists())
        active = UPGRADE._load_active(self.root / UPGRADE.UPGRADES_DIRECTORY)
        assert active is not None
        _transaction, loaded_plan, _payload, progress = UPGRADE._load_transaction(
            self.root / UPGRADE.UPGRADES_DIRECTORY,
            active,
        )
        self.assertEqual(loaded_plan, plan_document)
        self.assertEqual(progress["details"]["active_attempt"], 1)
        self.assertEqual(len(progress["details"]["attempts"]), 1)

    def test_incomplete_seal_is_quarantined_and_fresh_attempt_is_used(self) -> None:
        state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        self._set_maintenance(state)
        _desired, manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        ready = {
            "candidate_container_id": CANDIDATE_REVIEWER_ID,
            "candidate_image_id": CANDIDATE_IMAGE_ID,
            "deployment_digest": "sha256:" + "8" * 64,
            "processing_gate": gate,
        }
        UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.REPLACING,
            {
                "candidate_image_id": CANDIDATE_IMAGE_ID,
                "initial_classification": UPGRADE.OLD,
                "processing_gate": gate,
            },
        )
        UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.REVIEWER_READY,
            ready,
        )
        attempt_one = UPGRADE._attempt_record(transaction, 1)
        progress = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.SEALING,
            UPGRADE._sealing_details(
                ready,
                [attempt_one],
                [],
                1,
                plan["sealed_state_directory"],
            ),
        )
        Path(attempt_one["path"]).mkdir(mode=0o700)

        def fake_seal(
            args,
            runner,
            *,
            lock_descriptor,
            upgrade_inhibitor,
            expected_repository_root,
        ):
            self.assertEqual(
                expected_repository_root,
                self.root / "candidate-repository",
            )
            args.state_directory.mkdir(mode=0o700)

        inhibitor = UPGRADE._inhibitor_document(
            plan["project"],
            plan_document["plan_digest"],
        )
        with mock.patch.object(
            UPGRADE,
            "_sealed_state_valid",
            side_effect=[False, True, True],
        ), mock.patch.object(
            UPGRADE.reconciler,
            "seal",
            side_effect=fake_seal,
        ):
            sealed = UPGRADE._seal_candidate(
                transaction,
                plan_document,
                plan,
                progress,
                manifest,
                transaction / UPGRADE.CANDIDATE_COMPOSE_FILE,
                ready,
                mock.Mock(),
                91,
                inhibitor,
            )
        self.assertEqual(sealed["phase"], UPGRADE.SEALED_MAINTENANCE)
        self.assertEqual(sealed["details"]["active_attempt"], 2)
        self.assertEqual(sealed["details"]["quarantined_attempts"], [1])
        self.assertEqual(len(sealed["details"]["attempts"]), 2)
        self.assertTrue((transaction / "quarantine-seal-attempt-1").is_dir())
        self.assertTrue(Path(plan["sealed_state_directory"]).is_dir())

    def test_recovered_sealed_rename_is_fsynced_before_checkpoint(self) -> None:
        (
            transaction,
            plan_document,
            plan,
            manifest,
            ready,
            attempt,
            progress,
        ) = self._checkpoint_active_sealing()
        attempt_path = Path(attempt["path"])
        sealed = Path(plan["sealed_state_directory"])
        attempt_path.mkdir(mode=0o700)
        os.rename(attempt_path, sealed)

        real_fsync = os.fsync
        real_checkpoint = UPGRADE._checkpoint
        fsyncs: list[int] = []

        def track_fsync(descriptor: int) -> None:
            fsyncs.append(descriptor)
            real_fsync(descriptor)

        def checkpoint(*args, **kwargs):
            phase = args[2]
            if phase == UPGRADE.SEALED_MAINTENANCE:
                self.assertGreaterEqual(len(fsyncs), 1)
            return real_checkpoint(*args, **kwargs)

        with mock.patch.object(
            UPGRADE,
            "_sealed_state_valid",
            return_value=True,
        ), mock.patch.object(
            UPGRADE.os,
            "fsync",
            side_effect=track_fsync,
        ), mock.patch.object(
            UPGRADE,
            "_checkpoint",
            side_effect=checkpoint,
        ):
            result = UPGRADE._seal_candidate(
                transaction,
                plan_document,
                plan,
                progress,
                manifest,
                transaction / UPGRADE.CANDIDATE_COMPOSE_FILE,
                ready,
                mock.Mock(),
                91,
                UPGRADE._inhibitor_document(
                    plan["project"],
                    plan_document["plan_digest"],
                ),
            )
        self.assertEqual(result["phase"], UPGRADE.SEALED_MAINTENANCE)

    def test_recovered_quarantine_rename_is_fsynced_before_checkpoint(self) -> None:
        (
            transaction,
            plan_document,
            plan,
            manifest,
            ready,
            attempt,
            progress,
        ) = self._checkpoint_active_sealing()
        attempt_path = Path(attempt["path"])
        quarantine = transaction / "quarantine-seal-attempt-1"
        attempt_path.mkdir(mode=0o700)
        os.rename(attempt_path, quarantine)

        real_fsync = os.fsync
        real_checkpoint = UPGRADE._checkpoint
        fsyncs: list[int] = []

        def track_fsync(descriptor: int) -> None:
            fsyncs.append(descriptor)
            real_fsync(descriptor)

        def checkpoint(*args, **kwargs):
            phase = args[2]
            details = args[3]
            if (
                phase == UPGRADE.SEALING
                and details.get("quarantined_attempts") == [1]
                and details.get("active_attempt") is None
            ):
                self.assertGreaterEqual(len(fsyncs), 1)
                real_checkpoint(*args, **kwargs)
                raise RuntimeError("stop after recovered quarantine checkpoint")
            return real_checkpoint(*args, **kwargs)

        with mock.patch.object(
            UPGRADE.os,
            "fsync",
            side_effect=track_fsync,
        ), mock.patch.object(
            UPGRADE,
            "_checkpoint",
            side_effect=checkpoint,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "recovered quarantine",
            ):
                UPGRADE._seal_candidate(
                    transaction,
                    plan_document,
                    plan,
                    progress,
                    manifest,
                    transaction / UPGRADE.CANDIDATE_COMPOSE_FILE,
                    ready,
                    mock.Mock(),
                    91,
                    UPGRADE._inhibitor_document(
                        plan["project"],
                        plan_document["plan_digest"],
                    ),
                )
        recovered = self._progress(transaction, plan_document)
        self.assertEqual(recovered["phase"], UPGRADE.SEALING)
        self.assertEqual(recovered["details"]["quarantined_attempts"], [1])
        self.assertIsNone(recovered["details"]["active_attempt"])

    def test_active_selector_hardlink_crash_state_is_repaired(self) -> None:
        _state, _candidate, _transaction, _plan_document, _plan = self._prepare()
        upgrades = self.root / UPGRADE.UPGRADES_DIRECTORY
        active = upgrades / UPGRADE.ACTIVE_FILE
        staging = upgrades / UPGRADE.ACTIVE_STAGING_FILE
        os.link(active, staging)
        self.assertEqual(active.lstat().st_nlink, 2)
        result = UPGRADE.status(self.root)
        self.assertEqual(result["phase"], UPGRADE.QUIESCING)
        self.assertFalse(staging.exists())
        self.assertEqual(active.lstat().st_nlink, 1)

    def test_unpublished_active_staging_is_discarded_not_promoted(self) -> None:
        upgrades = self.root / UPGRADE.UPGRADES_DIRECTORY
        upgrades.mkdir(mode=0o700)
        staging = upgrades / UPGRADE.ACTIVE_STAGING_FILE
        staging.write_bytes(b"partial-precommit")
        staging.chmod(0o600)
        self.assertIsNone(UPGRADE._load_active(upgrades, optional=True))
        self.assertFalse(staging.exists())
        self.assertFalse((upgrades / UPGRADE.ACTIVE_FILE).exists())

    def test_candidate_projection_rejects_extra_runtime_drift(self) -> None:
        source = {
            "config": {
                "Image": "tacua-reviewer-web:old",
                "Labels": {
                    "com.docker.compose.config-hash": "3" * 64,
                    "com.docker.compose.image": OLD_IMAGE_ID,
                    "com.docker.compose.project": "reconcile-test",
                },
            },
            "host": {"ReadonlyRootfs": True},
            "id": OLD_REVIEWER_ID,
            "image_id": OLD_IMAGE_ID,
            "mounts": [],
            "name": "/reconcile-test-reviewer-1",
            "networks": {},
        }
        candidate = deepcopy(source)
        candidate["config"]["Image"] = "tacua-reviewer-web:candidate"
        candidate["config"]["Labels"]["com.docker.compose.config-hash"] = (
            "4" * 64
        )
        candidate["config"]["Labels"]["com.docker.compose.image"] = (
            CANDIDATE_IMAGE_ID
        )
        candidate["id"] = CANDIDATE_REVIEWER_ID
        candidate["image_id"] = CANDIDATE_IMAGE_ID
        self.assertTrue(
            UPGRADE._candidate_projection(
                candidate,
                source,
                candidate_ref="tacua-reviewer-web:candidate",
                candidate_id=CANDIDATE_IMAGE_ID,
            )
        )
        candidate["host"]["ReadonlyRootfs"] = False
        self.assertFalse(
            UPGRADE._candidate_projection(
                candidate,
                source,
                candidate_ref="tacua-reviewer-web:candidate",
                candidate_id=CANDIDATE_IMAGE_ID,
            )
        )

    def test_promotion_checkpoint_crash_retries_exact_promotion_action(self) -> None:
        _state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        evidence = self._finalization_evidence(gate)
        promoting = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.PROMOTING,
            {"processing_gate": gate},
        )
        fake_bindings = mock.Mock()
        fake_bindings.target_units.digests.return_value = evidence[
            "target_digests"
        ]
        promote = mock.Mock(return_value=(91, evidence["promotion"]))
        real_checkpoint = UPGRADE._checkpoint

        def crash_after_promotion(
            selected_transaction,
            selected_plan,
            phase,
            details,
        ):
            if phase == UPGRADE.SCHEDULED_MAINTENANCE:
                raise UPGRADE.UpgradeError("CRASH_AFTER_PROMOTION")
            return real_checkpoint(
                selected_transaction,
                selected_plan,
                phase,
                details,
            )

        with mock.patch.object(
            UPGRADE,
            "_finalize_bindings",
            return_value=fake_bindings,
        ), mock.patch.object(
            UPGRADE.finalize,
            "promote_target_maintenance",
            promote,
        ), mock.patch.object(
            UPGRADE,
            "_checkpoint",
            side_effect=crash_after_promotion,
        ):
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "CRASH_AFTER_PROMOTION",
            ):
                UPGRADE._drive_finalization(
                    transaction,
                    plan_document,
                    plan,
                    promoting,
                    gate,
                    mock.Mock(),
                    {"descriptor": 91},
                )
        durable = self._progress(transaction, plan_document)
        self.assertEqual(durable["phase"], UPGRADE.PROMOTING)
        with mock.patch.object(
            UPGRADE,
            "_finalize_bindings",
            return_value=fake_bindings,
        ), mock.patch.object(
            UPGRADE.finalize,
            "promote_target_maintenance",
            promote,
        ), mock.patch.object(
            UPGRADE.finalize,
            "activate_target",
            return_value=(91, evidence["activation"]),
        ), mock.patch.object(
            UPGRADE.finalize,
            "remove_processing_gate",
            return_value=(91, evidence["removal"]),
        ), mock.patch.object(
            UPGRADE.finalize,
            "prove_later_scheduled_reconcile",
            return_value=(91, evidence["scheduled"]),
        ):
            complete = UPGRADE._drive_finalization(
                transaction,
                plan_document,
                plan,
                durable,
                gate,
                mock.Mock(),
                {"descriptor": 91},
            )
        self.assertEqual(complete["phase"], UPGRADE.COMPLETE)
        self.assertEqual(promote.call_count, 2)

    def test_scheduled_proof_checkpoint_crash_retries_proof(self) -> None:
        _state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        evidence = self._finalization_evidence(gate)
        gate_absent = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.ACTIVATING,
            UPGRADE._activating_details(
                gate,
                evidence["promotion"],
                UPGRADE.ACTIVATION_GATE_ABSENT,
                activation_receipt=evidence["activation"],
                gate_removal_receipt=evidence["removal"],
            ),
        )
        fake_bindings = mock.Mock()
        proof = mock.Mock(return_value=(91, evidence["scheduled"]))
        real_checkpoint = UPGRADE._checkpoint

        def crash_after_proof(
            selected_transaction,
            selected_plan,
            phase,
            details,
        ):
            if phase == UPGRADE.COMPLETE:
                raise UPGRADE.UpgradeError("CRASH_AFTER_SCHEDULED_PROOF")
            return real_checkpoint(
                selected_transaction,
                selected_plan,
                phase,
                details,
            )

        with mock.patch.object(
            UPGRADE,
            "_finalize_bindings",
            return_value=fake_bindings,
        ), mock.patch.object(
            UPGRADE.finalize,
            "prove_later_scheduled_reconcile",
            proof,
        ), mock.patch.object(
            UPGRADE,
            "_checkpoint",
            side_effect=crash_after_proof,
        ):
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "CRASH_AFTER_SCHEDULED_PROOF",
            ):
                UPGRADE._drive_finalization(
                    transaction,
                    plan_document,
                    plan,
                    gate_absent,
                    gate,
                    mock.Mock(),
                    {"descriptor": 91},
                )
        durable = self._progress(transaction, plan_document)
        self.assertEqual(
            durable["details"]["substage"],
            UPGRADE.ACTIVATION_GATE_ABSENT,
        )
        with mock.patch.object(
            UPGRADE,
            "_finalize_bindings",
            return_value=fake_bindings,
        ), mock.patch.object(
            UPGRADE.finalize,
            "prove_later_scheduled_reconcile",
            proof,
        ):
            complete = UPGRADE._drive_finalization(
                transaction,
                plan_document,
                plan,
                durable,
                gate,
                mock.Mock(),
                {"descriptor": 91},
            )
        self.assertEqual(complete["phase"], UPGRADE.COMPLETE)
        self.assertEqual(proof.call_count, 2)

    def test_complete_receipt_is_reused_before_active_selector_unlink(self) -> None:
        _state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        evidence = self._finalization_evidence(gate)
        complete = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.COMPLETE,
            self._complete_finalization_details(gate, evidence),
        )
        fake_bindings = mock.Mock()
        with mock.patch.object(
            UPGRADE,
            "_finalize_bindings",
            return_value=fake_bindings,
        ):
            first = UPGRADE._drive_finalization(
                transaction,
                plan_document,
                plan,
                complete,
                gate,
                mock.Mock(),
                {"descriptor": 91},
            )
        receipt = UPGRADE.journal.load_receipt(transaction, plan_document)
        self.assertIsNotNone(receipt)
        upgrades = self.root / UPGRADE.UPGRADES_DIRECTORY
        active = UPGRADE._load_active(upgrades)
        self.assertIsNotNone(active)
        with mock.patch.object(
            UPGRADE,
            "_finalize_bindings",
            return_value=fake_bindings,
        ), mock.patch.object(
            UPGRADE.journal,
            "write_receipt",
        ) as write:
            second = UPGRADE._drive_finalization(
                transaction,
                plan_document,
                plan,
                first,
                gate,
                mock.Mock(),
                {"descriptor": 91},
            )
        write.assert_not_called()
        self.assertEqual(second, first)
        assert active is not None
        UPGRADE._clear_active(upgrades, active)
        with mock.patch.object(
            UPGRADE,
            "_fsync_validated_directory",
            wraps=UPGRADE._fsync_validated_directory,
        ) as durable_idle:
            result = UPGRADE.resume(self.root)
        self.assertEqual(
            result,
            {"code": "REVIEWER_UPGRADE_IDLE", "status": "idle"},
        )
        durable_idle.assert_called_once_with(upgrades)

    def test_active_unlink_before_directory_fsync_resumes_idle_or_retries(self) -> None:
        _state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        evidence = self._finalization_evidence(gate)
        complete = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.COMPLETE,
            self._complete_finalization_details(gate, evidence),
        )
        with mock.patch.object(
            UPGRADE,
            "_finalize_bindings",
            return_value=mock.Mock(),
        ):
            UPGRADE._drive_finalization(
                transaction,
                plan_document,
                plan,
                complete,
                gate,
                mock.Mock(),
                {"descriptor": 91},
            )
        upgrades = self.root / UPGRADE.UPGRADES_DIRECTORY
        active = UPGRADE._load_active(upgrades)
        assert active is not None
        with mock.patch.object(
            UPGRADE.reconciler,
            "_fsync_directory",
            side_effect=OSError("simulated crash window"),
        ):
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "REVIEWER_UPGRADE_STATE_INVALID",
            ):
                UPGRADE._clear_active(upgrades, active)
        self.assertFalse((upgrades / UPGRADE.ACTIVE_FILE).exists())
        # If the unlink survives, resume is idle.  If a real crash loses that
        # directory update, COMPLETE + its immutable receipt is safely retried.
        with mock.patch.object(
            UPGRADE,
            "_fsync_validated_directory",
            wraps=UPGRADE._fsync_validated_directory,
        ) as durable_idle:
            result = UPGRADE.resume(self.root)
        self.assertEqual(
            result,
            {"code": "REVIEWER_UPGRADE_IDLE", "status": "idle"},
        )
        durable_idle.assert_called_once_with(upgrades)

    def test_directory_helpers_close_each_opened_descriptor_exactly_once(self) -> None:
        directory = self.root / "descriptor-lifetime"
        directory.mkdir(mode=0o700)
        real_open = os.open
        real_close = os.close

        for operation in (
            lambda: UPGRADE._active_directory_lock(directory),
            lambda: nullcontext(UPGRADE._fsync_validated_directory(directory)),
        ):
            with self.subTest(operation=operation):
                opened: list[int] = []

                def track_open(*args, **kwargs):
                    descriptor = real_open(*args, **kwargs)
                    opened.append(descriptor)
                    return descriptor

                with mock.patch.object(
                    UPGRADE.os,
                    "open",
                    side_effect=track_open,
                ), mock.patch.object(
                    UPGRADE.os,
                    "close",
                    side_effect=real_close,
                ) as close:
                    with operation():
                        pass
                self.assertEqual(len(opened), 1)
                self.assertEqual(close.call_args_list, [mock.call(opened[0])])

    def test_prepare_lock_requires_and_creates_the_exact_shared_path(self) -> None:
        project = "reconcile-test"
        expected = UPGRADE.reconciler._lock_path(project)
        serial = self.root / UPGRADE.SERIAL_LOCK_FILE
        with mock.patch.object(
            UPGRADE.reconciler,
            "_open_host_lock",
            return_value=74,
        ) as opened, mock.patch.object(
            UPGRADE.reconciler,
            "_release_lock",
        ) as released:
            result = UPGRADE.prepare_lock(serial, expected, project)
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(
            opened.call_args_list,
            [mock.call(expected, create=True)],
        )
        self.assertEqual(
            released.call_args_list,
            [mock.call(74)],
        )
        with self.assertRaisesRegex(
            UPGRADE.UpgradeError,
            "REVIEWER_UPGRADE_INPUT_INVALID",
        ):
            UPGRADE.prepare_lock(
                self.root / "wrong.lock",
                Path("/tmp/wrong.lock"),
                project,
            )

    def test_reboot_rebind_is_durable_and_reused_after_pre_phase_crash(self) -> None:
        processing = self.root / "ephemeral-processing.lock"
        next_boot = "00000000-0000-4000-8000-000000000002"
        with mock.patch.object(
            UPGRADE.reconciler,
            "_lock_path",
            return_value=processing,
        ), mock.patch.object(
            UPGRADE,
            "_drive_processing_gate",
            side_effect=self._leave_processing_gate_uncheckpointed,
        ) as drive_gate:
            state, _candidate, transaction, plan_document, plan = (
                self._prepare_with_real_processing_lock(processing)
            )
            before = self._progress(transaction, plan_document)
            replacement = self._replace_processing_lock_inode(processing)
            real_load_active = UPGRADE._load_active
            active_loads = 0

            def crash_after_epoch(upgrades, *, optional=False):
                nonlocal active_loads
                active_loads += 1
                if active_loads == 2:
                    raise RuntimeError("crash after epoch publication")
                return real_load_active(upgrades, optional=optional)

            with mock.patch.object(
                UPGRADE,
                "_current_boot_id",
                return_value=next_boot,
            ), mock.patch.object(
                UPGRADE,
                "_load_active",
                side_effect=crash_after_epoch,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "epoch publication",
                ):
                    UPGRADE.resume(
                        self.root,
                        **self._upgrade_abi(state),
                        runner=self._runner,
                    )

            self.assertEqual(self._progress(transaction, plan_document), before)
            rebound = UPGRADE._load_processing_lock_epoch(
                transaction,
                plan_document,
                plan,
            )
            self.assertEqual(rebound["sequence"], 1)
            self.assertEqual(rebound["boot_id"], next_boot)
            self.assertEqual(
                (
                    rebound["lock_file_binding"]["device"],
                    rebound["lock_file_binding"]["inode"],
                ),
                (replacement.st_dev, replacement.st_ino),
            )
            sidecar = transaction / "processing-lock-epoch-00000001.json"
            self.assertEqual(stat.S_IMODE(sidecar.lstat().st_mode), 0o600)

            with mock.patch.object(
                UPGRADE,
                "_current_boot_id",
                return_value=next_boot,
            ), mock.patch.object(
                UPGRADE,
                "_publish_processing_lock_epoch",
                wraps=UPGRADE._publish_processing_lock_epoch,
            ) as publish:
                result = UPGRADE.resume(
                    self.root,
                    **self._upgrade_abi(state),
                    runner=self._runner,
                )
            self.assertEqual(result["status"], "waiting_pre_replacement")
            publish.assert_not_called()
            self.assertEqual(self._progress(transaction, plan_document), before)
            self.assertEqual(drive_gate.call_count, 2)

    def test_same_boot_processing_lock_replacement_is_fatal(self) -> None:
        processing = self.root / "ephemeral-processing.lock"
        with mock.patch.object(
            UPGRADE.reconciler,
            "_lock_path",
            return_value=processing,
        ), mock.patch.object(
            UPGRADE,
            "_drive_processing_gate",
            side_effect=self._leave_processing_gate_uncheckpointed,
        ) as drive_gate:
            state, _candidate, transaction, plan_document, _plan = (
                self._prepare_with_real_processing_lock(processing)
            )
            before = self._progress(transaction, plan_document)
            self._replace_processing_lock_inode(processing)
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "UPGRADE_FINALIZE_LOCK_INVALID",
            ):
                UPGRADE.resume(
                    self.root,
                    **self._upgrade_abi(state),
                    runner=self._runner,
                )
            self.assertEqual(self._progress(transaction, plan_document), before)
            self.assertFalse(
                (transaction / "processing-lock-epoch-00000001.json").exists()
            )
            # Prepare called the gate driver; the rejected resume did not.
            self.assertEqual(drive_gate.call_count, 1)

    def test_processing_lock_epoch_chain_rejects_malformed_histories(self) -> None:
        _state, _candidate, transaction, plan_document, plan = self._prepare()
        initial = plan["finalize"]["processing_lock_epoch"]
        next_boot = "00000000-0000-4000-8000-000000000002"

        def record(
            sequence: int,
            boot_id: str,
            previous_digest: str,
        ) -> dict:
            value = {
                "boot_id": boot_id,
                "contract_version": UPGRADE.PROCESSING_LOCK_EPOCH_CONTRACT,
                "epoch_digest": "",
                "lock_file_binding": deepcopy(
                    initial["lock_file_binding"]
                ),
                "plan_digest": plan_document["plan_digest"],
                "previous_epoch_digest": previous_digest,
                "sequence": sequence,
            }
            value["epoch_digest"] = UPGRADE._epoch_digest(value)
            return value

        cases = {
            "malformed": (
                1,
                b"{}",
            ),
            "gapped": (
                2,
                UPGRADE.journal.canonical_json(
                    record(2, next_boot, initial["epoch_digest"])
                ),
            ),
            "forked": (
                1,
                UPGRADE.journal.canonical_json(
                    record(1, next_boot, "sha256:" + "f" * 64)
                ),
            ),
            "repeated_boot": (
                1,
                UPGRADE.journal.canonical_json(
                    record(1, initial["boot_id"], initial["epoch_digest"])
                ),
            ),
        }
        for label, (sequence, payload) in cases.items():
            with self.subTest(label=label):
                path = transaction / (
                    f"processing-lock-epoch-{sequence:08d}.json"
                )
                path.write_bytes(payload)
                path.chmod(0o600)
                try:
                    with self.assertRaisesRegex(
                        UPGRADE.UpgradeError,
                        "UPGRADE_FINALIZE_LOCK_INVALID",
                    ):
                        UPGRADE._load_processing_lock_epoch(
                            transaction,
                            plan_document,
                            plan,
                        )
                finally:
                    path.unlink()

    def test_prepare_contention_is_retryable_before_transaction_mutation(self) -> None:
        state, candidate = self._fixture()
        serial = self.root / UPGRADE.SERIAL_LOCK_FILE
        with UPGRADE._upgrade_serialization_lock(
            self.root,
            serial,
        ):
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "REVIEWER_UPGRADE_LOCK_CONTENDED",
            ):
                UPGRADE.prepare(
                    state,
                    candidate,
                    **self._upgrade_abi(state),
                    serial_lock_file=serial,
                    runner=self._runner,
                    operation_id="contended-prepare",
                )
        self.assertFalse((self.root / UPGRADE.UPGRADES_DIRECTORY).exists())
        self.assertEqual(
            UPGRADE._failure_exit_status("REVIEWER_UPGRADE_LOCK_CONTENDED"),
            1,
        )

    def test_resume_contention_cannot_advance_the_journal(self) -> None:
        _state, _candidate, transaction, plan_document, _plan = self._prepare()
        before = self._progress(transaction, plan_document)
        serial = self.root / UPGRADE.SERIAL_LOCK_FILE
        with UPGRADE._upgrade_serialization_lock(
            self.root,
            serial,
        ):
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "REVIEWER_UPGRADE_LOCK_CONTENDED",
            ):
                UPGRADE.resume(self.root, serial_lock_file=serial)
        self.assertEqual(self._progress(transaction, plan_document), before)

    def test_lock_prerequisite_succeeds_while_bootstrap_holds_serial_lock(self) -> None:
        project = "reconcile-test"
        serial = self.root / UPGRADE.SERIAL_LOCK_FILE
        processing = UPGRADE.reconciler._lock_path(project)
        with UPGRADE._upgrade_serialization_lock(
            self.root,
            serial,
        ) as (_descriptor, before, _path), mock.patch.object(
            UPGRADE.reconciler,
            "_open_host_lock",
            return_value=74,
        ), mock.patch.object(
            UPGRADE.reconciler,
            "_release_lock",
        ):
            result = UPGRADE.prepare_lock(serial, processing, project)
            opened = os.open(
                serial,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                after = UPGRADE.reconciler._validate_lock_descriptor(
                    opened,
                    serial,
                )
            finally:
                os.close(opened)
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(before, after)

    def test_borrowed_processing_descriptor_is_rejected_before_handoff(self) -> None:
        _state, _candidate, transaction, plan_document, plan = self._prepare()
        gate = self._gate(transaction, plan_document, plan)
        promoting = UPGRADE._checkpoint(
            transaction,
            plan_document,
            UPGRADE.PROMOTING,
            {"processing_gate": gate},
        )
        with mock.patch.object(
            UPGRADE,
            "_finalize_bindings",
        ) as build:
            with self.assertRaisesRegex(
                UPGRADE.UpgradeError,
                "UPGRADE_FINALIZE_LOCK_INVALID",
            ):
                UPGRADE._drive_finalization(
                    transaction,
                    plan_document,
                    plan,
                    promoting,
                    gate,
                    mock.Mock(),
                    {"borrowed": 1, "descriptor": 91},
                )
        build.assert_not_called()

    def test_resume_main_reports_idle_and_exits_zero(self) -> None:
        output = mock.Mock(buffer=io.BytesIO())
        error = mock.Mock(buffer=io.BytesIO())
        with mock.patch.object(UPGRADE.sys, "stdout", output), mock.patch.object(
            UPGRADE.sys,
            "stderr",
            error,
        ):
            status = UPGRADE.main(
                [
                    "resume",
                    "--state-parent",
                    str(self.root),
                    "--unit-directory",
                    str(self.root),
                    "--lock-file",
                    "/tmp/tacua-compose-processing-reconcile-test.lock",
                    "--operation-directory",
                    str(self.root),
                    "--serial-lock-file",
                    str(self.root / UPGRADE.SERIAL_LOCK_FILE),
                ]
            )
        self.assertEqual(status, 0)
        self.assertEqual(
            output.buffer.getvalue(),
            UPGRADE.journal.canonical_json(
                {"code": "REVIEWER_UPGRADE_IDLE", "status": "idle"}
            )
            + b"\n",
        )
        self.assertEqual(error.buffer.getvalue(), b"")

    def test_main_uses_78_for_manual_state_and_one_for_retryable_failure(self) -> None:
        cases = (
            ("REVIEWER_UPGRADE_STATE_INVALID", 78),
            ("UPGRADE_FINALIZE_UNIT_UNKNOWN", 78),
            ("REVIEWER_UPGRADE_BACKUP_FAILED", 1),
        )
        for code, expected in cases:
            with self.subTest(code=code):
                output = mock.Mock(buffer=io.BytesIO())
                error = mock.Mock(buffer=io.BytesIO())
                with mock.patch.object(
                    UPGRADE,
                    "resume",
                    side_effect=UPGRADE.UpgradeError(code),
                ), mock.patch.object(
                    UPGRADE.sys,
                    "stdout",
                    output,
                ), mock.patch.object(
                    UPGRADE.sys,
                    "stderr",
                    error,
                ):
                    status = UPGRADE.main(
                        [
                            "resume",
                            "--state-parent",
                            str(self.root),
                            "--unit-directory",
                            str(self.root),
                            "--lock-file",
                            "/tmp/tacua-compose-processing-reconcile-test.lock",
                            "--operation-directory",
                            str(self.root),
                            "--serial-lock-file",
                            str(self.root / UPGRADE.SERIAL_LOCK_FILE),
                        ]
                    )
                self.assertEqual(status, expected)
                self.assertEqual(output.buffer.getvalue(), b"")
                self.assertEqual(
                    error.buffer.getvalue(),
                    UPGRADE.journal.canonical_json(
                        {"code": code, "status": "failed"}
                    )
                    + b"\n",
                )

    def test_every_resumer_failure_code_has_an_explicit_exit_policy(self) -> None:
        self.assertFalse(
            UPGRADE.FATAL_FAILURE_CODES & UPGRADE.RETRYABLE_FAILURE_CODES
        )
        cases = {
            **{code: 78 for code in UPGRADE.FATAL_FAILURE_CODES},
            **{code: 1 for code in UPGRADE.RETRYABLE_FAILURE_CODES},
        }
        self.assertGreater(len(cases), 70)
        for code, expected in sorted(cases.items()):
            with self.subTest(code=code):
                self.assertEqual(UPGRADE._failure_exit_status(code), expected)
        self.assertEqual(
            UPGRADE._failure_exit_status("UPGRADE_FUTURE_UNKNOWN"),
            78,
        )
        emitted: set[str] = set()
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = node.func
            name = (
                function.id
                if isinstance(function, ast.Name)
                else function.attr
                if isinstance(function, ast.Attribute)
                else ""
            )
            first = node.args[0]
            if (
                name in {"UpgradeError", "_fail"}
                and isinstance(first, ast.Constant)
                and isinstance(first.value, str)
                and first.value.startswith(
                    ("RECONCILE_", "REVIEWER_", "UPGRADE_")
                )
            ):
                emitted.add(first.value)
        self.assertEqual(emitted - set(cases), set())

    def test_exhausted_abandonment_retains_evidence_and_permits_fresh_selector(
        self,
    ) -> None:
        state, transaction, _document, _plan, _progress, _gate = (
            self._checkpoint_exhausted_backup()
        )
        preserved_paths = [
            transaction / UPGRADE.journal.PLAN_FILE,
            transaction / UPGRADE.journal.PROGRESS_FILE,
            transaction / UPGRADE.backup.BACKUP_LEDGER_FILE,
            *[
                transaction
                / f"backup-quarantine-{number:02d}"
                / UPGRADE.backup.ATTEMPT_MARKER_FILE
                for number in range(1, 4)
            ],
        ]
        preserved = {path: path.read_bytes() for path in preserved_paths}
        patches = self._abandon_patches(state)
        with patches[0], patches[1], patches[2] as set_running, patches[3], patches[4]:
            result = ABANDON.abandon_exhausted_backup(
                self.root,
                "reviewer-test-operation",
                serial_lock_file=self.root / UPGRADE.SERIAL_LOCK_FILE,
                runner=mock.Mock(),
            )

        self.assertEqual(result["status"], "abandoned")
        self.assertEqual(set_running.call_count, 1)
        self.assertFalse(
            (self.root / UPGRADE.UPGRADES_DIRECTORY / UPGRADE.ACTIVE_FILE).exists()
        )
        retired = transaction / ABANDON.RETIRED_ACTIVE_FILE
        self.assertTrue(retired.is_file())
        self.assertEqual(retired.lstat().st_nlink, 1)
        receipt = ABANDON._existing_receipt(transaction)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["status"], "abandoned")
        self.assertEqual(
            receipt["backup_evidence"]["sequence"],
            UPGRADE.backup.MAX_BACKUP_ATTEMPTS,
        )
        for path, payload in preserved.items():
            self.assertEqual(path.read_bytes(), payload)
        desired, _manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        self.assertEqual(desired["desired"], "running")
        self.assertFalse(Path(_gate["operation_directory"]).exists())

        upgrades = self.root / UPGRADE.UPGRADES_DIRECTORY
        fresh = UPGRADE._publish_active(
            upgrades,
            "reviewer-fresh-operation",
            "sha256:" + "f" * 64,
        )
        self.assertEqual(fresh["operation_id"], "reviewer-fresh-operation")
        UPGRADE._clear_active(upgrades, fresh)

    def test_abandonment_recovers_after_running_before_gate_removal(self) -> None:
        state, transaction, _document, _plan, _progress, gate = (
            self._checkpoint_exhausted_backup()
        )
        patches = self._abandon_patches(state)
        with patches[0], patches[1], patches[2], patches[3], patches[4], mock.patch.object(
            ABANDON,
            "_remove_gate",
            side_effect=ABANDON.AbandonError(ABANDON._RECOVERY_FAILED),
        ):
            with self.assertRaises(ABANDON.AbandonError):
                ABANDON.abandon_exhausted_backup(
                    self.root,
                    "reviewer-test-operation",
                    serial_lock_file=self.root / UPGRADE.SERIAL_LOCK_FILE,
                    runner=mock.Mock(),
                )
        desired, _manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        self.assertEqual(desired["desired"], "running")
        self.assertTrue(Path(gate["operation_directory"]).exists())
        self.assertIsNone(ABANDON._existing_receipt(transaction))

        patches = self._abandon_patches(state)
        with patches[0], patches[1], patches[2] as set_running, patches[3], patches[4]:
            result = ABANDON.abandon_exhausted_backup(
                self.root,
                "reviewer-test-operation",
                serial_lock_file=self.root / UPGRADE.SERIAL_LOCK_FILE,
                runner=mock.Mock(),
            )
        self.assertEqual(result["status"], "abandoned")
        self.assertEqual(set_running.call_count, 1)

    def test_abandonment_recovers_empty_gate_directory_and_missing_receipt(
        self,
    ) -> None:
        state, transaction, _document, _plan, _progress, gate = (
            self._checkpoint_exhausted_backup()
        )
        operation = Path(gate["operation_directory"])
        real_rmdir = os.rmdir
        failed = False

        def interrupt_rmdir(path, *args, **kwargs):
            nonlocal failed
            if not failed and path == operation.name:
                failed = True
                raise OSError("synthetic interruption")
            return real_rmdir(path, *args, **kwargs)

        patches = self._abandon_patches(state)
        with patches[0], patches[1], patches[2], patches[3], patches[4], mock.patch.object(
            ABANDON.os,
            "rmdir",
            side_effect=interrupt_rmdir,
        ):
            with self.assertRaises(ABANDON.AbandonError):
                ABANDON.abandon_exhausted_backup(
                    self.root,
                    "reviewer-test-operation",
                    serial_lock_file=self.root / UPGRADE.SERIAL_LOCK_FILE,
                    runner=mock.Mock(),
                )
        self.assertTrue(operation.is_dir())
        self.assertEqual(list(operation.iterdir()), [])
        self.assertEqual(
            ABANDON._gate_state(ABANDON._processing_gate_binding(gate)),
            "empty",
        )

        patches = self._abandon_patches(state)
        with patches[0], patches[1], patches[2] as set_running, patches[3], patches[4]:
            result = ABANDON.abandon_exhausted_backup(
                self.root,
                "reviewer-test-operation",
                serial_lock_file=self.root / UPGRADE.SERIAL_LOCK_FILE,
                runner=mock.Mock(),
            )
        self.assertEqual(result["status"], "abandoned")
        self.assertEqual(set_running.call_count, 0)
        self.assertIsNotNone(ABANDON._existing_receipt(transaction))

    def test_abandonment_recovers_receipt_and_selector_hardlink_windows(self) -> None:
        state, transaction, _document, _plan, _progress, _gate = (
            self._checkpoint_exhausted_backup()
        )
        patches = self._abandon_patches(state)
        with patches[0], patches[1], patches[2], patches[3], patches[4], mock.patch.object(
            ABANDON,
            "_retire_active",
            side_effect=ABANDON.AbandonError(ABANDON._STATE_CHANGED),
        ):
            with self.assertRaises(ABANDON.AbandonError):
                ABANDON.abandon_exhausted_backup(
                    self.root,
                    "reviewer-test-operation",
                    serial_lock_file=self.root / UPGRADE.SERIAL_LOCK_FILE,
                    runner=mock.Mock(),
                )
        receipt = ABANDON._existing_receipt(transaction)
        self.assertIsNotNone(receipt)
        upgrades = self.root / UPGRADE.UPGRADES_DIRECTORY
        active = upgrades / UPGRADE.ACTIVE_FILE
        retired = transaction / ABANDON.RETIRED_ACTIVE_FILE
        os.link(active, retired, follow_symlinks=False)
        UPGRADE.reconciler._fsync_directory(transaction)
        self.assertEqual(active.lstat().st_nlink, 2)

        patches = self._abandon_patches(state)
        active_validator = mock.patch.object(
            ABANDON.upgrade,
            "_load_active_locked",
            side_effect=AssertionError("nlink=2 active validator invoked"),
        )
        with (
            patches[0],
            patches[1],
            patches[2] as set_running,
            patches[3],
            patches[4],
            active_validator,
        ):
            result = ABANDON.abandon_exhausted_backup(
                self.root,
                "reviewer-test-operation",
                serial_lock_file=self.root / UPGRADE.SERIAL_LOCK_FILE,
                runner=mock.Mock(),
            )
        self.assertEqual(result["status"], "abandoned")
        self.assertEqual(set_running.call_count, 0)
        self.assertFalse(active.exists())
        self.assertEqual(retired.lstat().st_nlink, 1)
        self.assertEqual(ABANDON._existing_receipt(transaction), receipt)

    def test_abandonment_rejects_bundle_or_later_artifact_before_mutation(self) -> None:
        state, transaction, _document, _plan, _progress, _gate = (
            self._checkpoint_exhausted_backup()
        )
        (transaction / UPGRADE.SEALED_STATE_DIRECTORY).mkdir(mode=0o700)
        patches = self._abandon_patches(state)
        with patches[0], patches[1], patches[2] as set_running, patches[3], patches[4]:
            with self.assertRaisesRegex(
                ABANDON.AbandonError,
                "REVIEWER_UPGRADE_ABANDON_NOT_EXHAUSTED",
            ):
                ABANDON.abandon_exhausted_backup(
                    self.root,
                    "reviewer-test-operation",
                    serial_lock_file=self.root / UPGRADE.SERIAL_LOCK_FILE,
                    runner=mock.Mock(),
                )
        self.assertEqual(set_running.call_count, 0)
        desired, _manifest, _compose = UPGRADE.reconciler._load_bound_state(state)
        self.assertEqual(desired["desired"], "maintenance")

    def test_abandonment_guard_supports_the_real_healthy_set_running_trace(
        self,
    ) -> None:
        state, _transaction, _document, _plan, _progress, gate = (
            self._checkpoint_exhausted_backup()
        )
        desired, manifest, compose = UPGRADE.reconciler._load_bound_state(
            state
        )
        self.assertEqual(desired["desired"], "maintenance")
        docker = UPGRADE.reconciler._docker_prefix(manifest)
        project_filter = (
            "label=com.docker.compose.project=" + manifest["project"]
        )
        backend_volume = next(
            mount["Name"]
            for mount in manifest["containers"]["backend"]["mounts"]
            if mount.get("Destination") == "/var/lib/tacua"
        )
        container_ids = {
            item["id"] for item in manifest["containers"].values()
        }
        backend_id = manifest["containers"]["backend"]["id"]
        daemon = manifest["daemon"]
        daemon_document = {
            "CgroupDriver": daemon["cgroup_driver"],
            "CgroupVersion": daemon["cgroup_version"],
            "DockerRootDir": daemon["docker_root_directory"],
            "ID": daemon["id"],
            "SecurityOptions": daemon["security_options"],
        }
        calls: list[tuple[list[str], int]] = []

        def trace_runner(argv, *, timeout):
            command = list(argv)
            calls.append((command, timeout))
            if command == [
                manifest["commands"]["systemctl"],
                "--user",
                "is-active",
                "--quiet",
                "--",
                manifest["commands"]["docker_service"],
            ]:
                return b""
            if command == [*docker, "info", "--format", "{{json .}}"]:
                return UPGRADE.reconciler._canonical(daemon_document)
            if command[-2:] == ["--filter", project_filter]:
                return ("\n".join(sorted(container_ids)) + "\n").encode(
                    "ascii"
                )
            if command[-2:] == ["--filter", f"volume={backend_volume}"]:
                return (backend_id + "\n").encode("ascii")
            raise AssertionError((command, timeout))

        guarded = ABANDON._without_docker_mutation(
            trace_runner,
            manifest,
            compose,
        )

        def inspect_deployment(
            selected_manifest,
            selected_compose,
            selected_runner,
            *,
            allow_missing_network_consumers=False,
        ):
            self.assertEqual(selected_manifest, manifest)
            self.assertEqual(selected_compose, compose)
            self.assertTrue(allow_missing_network_consumers)
            self.assertEqual(
                UPGRADE.reconciler._listed_container_ids(
                    selected_runner,
                    docker,
                    project_filter,
                    "RECONCILE_CONTAINER_DRIFT",
                ),
                container_ids,
            )
            self.assertEqual(
                UPGRADE.reconciler._listed_container_ids(
                    selected_runner,
                    docker,
                    f"volume={backend_volume}",
                    "RECONCILE_CONTAINER_DRIFT",
                ),
                {backend_id},
            )
            return {
                "containers": manifest["containers"],
                "resources": manifest["resources"],
            }, True

        with (
            mock.patch.object(
                UPGRADE.reconciler,
                "_adopt_host_lock",
                return_value=79,
            ),
            mock.patch.object(
                UPGRADE.reconciler,
                "_inspect_deployment",
                side_effect=inspect_deployment,
            ),
            mock.patch.object(
                UPGRADE.reconciler,
                "_tailnet_state",
                side_effect=[({}, False), ({}, True)],
            ),
            mock.patch.object(UPGRADE.reconciler, "_enable_serve"),
            mock.patch.object(UPGRADE.reconciler, "_smoke"),
        ):
            result = UPGRADE.reconciler.set_running(
                state,
                runner=guarded,
                lock_descriptor=79,
                upgrade_inhibitor=gate["inhibitor"],
            )

        self.assertEqual(
            result,
            {"code": "RECONCILE_RECOVERED", "status": "recovered"},
        )
        current, _manifest, _compose = UPGRADE.reconciler._load_bound_state(
            state
        )
        self.assertEqual(current["desired"], "running")
        self.assertIsNone(UPGRADE.reconciler._load_activation(state, current))
        self.assertEqual(len(calls), 4)
        self.assertEqual(
            [command[len(docker) :2 + len(docker)] for command, _ in calls[1:]],
            [["info", "--format"], ["container", "ls"], ["container", "ls"]],
        )
        self.assertFalse(
            any(
                action in command
                for command, _timeout in calls
                for action in ("start", "stop", "rm", "up")
            )
        )

    def test_abandonment_running_transition_denies_docker_recovery_mutations(
        self,
    ) -> None:
        state, _candidate = self._fixture()
        _desired, manifest, compose = UPGRADE.reconciler._load_bound_state(state)
        calls = []

        def runner(argv, *, timeout):
            calls.append((list(argv), timeout))
            return b"read-only\n"

        guarded = ABANDON._without_docker_mutation(runner, manifest, compose)
        read_only = [
            *ABANDON.reconciler._compose_prefix(manifest, compose),
            "ps",
            "--no-trunc",
            "-aq",
            "backend",
        ]
        self.assertEqual(guarded(read_only, timeout=30), b"read-only\n")
        container_read = [
            *ABANDON.reconciler._docker_prefix(manifest),
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={manifest['project']}",
        ]
        self.assertEqual(
            guarded(container_read, timeout=30),
            b"read-only\n",
        )
        with self.assertRaises(UPGRADE.reconciler.ReconcileError):
            guarded(
                [
                    *ABANDON.reconciler._compose_prefix(manifest, compose),
                    "start",
                    *UPGRADE.reconciler.SERVICES,
                ],
                timeout=60,
            )
        with self.assertRaises(UPGRADE.reconciler.ReconcileError):
            guarded(
                [
                    manifest["commands"]["systemctl"],
                    "--user",
                    "start",
                    "--",
                    manifest["commands"]["docker_service"],
                ],
                timeout=30,
            )
        with self.assertRaises(UPGRADE.reconciler.ReconcileError):
            guarded(
                [
                    *ABANDON.reconciler._docker_prefix(manifest),
                    "image",
                    "rm",
                    "unexpected-image",
                ],
                timeout=30,
            )
        with self.assertRaises(UPGRADE.reconciler.ReconcileError):
            guarded(
                [manifest["commands"]["docker"], "start", "deadbeef"],
                timeout=30,
            )
        with self.assertRaises(UPGRADE.reconciler.ReconcileError):
            guarded(
                [
                    manifest["commands"]["docker"],
                    "--host",
                    "unix:///run/user/1000/other.sock",
                    "container",
                    "rm",
                    "deadbeef",
                ],
                timeout=30,
            )
        self.assertEqual(calls, [(read_only, 30), (container_read, 30)])


if __name__ == "__main__":
    unittest.main()
