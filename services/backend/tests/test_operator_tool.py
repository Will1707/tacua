# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse


SOURCE = Path(__file__).resolve().parents[1] / "src"
REPOSITORY = SOURCE.parents[2]
import sys

sys.path.insert(0, str(SOURCE))

from tacua_backend.config import ConfigError, load_config  # noqa: E402
from tacua_backend.config_tool import compile_config_template  # noqa: E402
from tacua_backend.instance_lock import (  # noqa: E402
    InstanceLockError,
    acquire_state_instance_lock,
)
from tacua_backend.operator_tool import (  # noqa: E402
    OperatorError,
    create_backup,
    deployment_preflight,
    restore_backup,
    smoke_deployment,
    validate_compose_document,
    verify_backup,
)
import tacua_backend.operator_tool as operator_tool  # noqa: E402
from tacua_backend.service import PilotBackend  # noqa: E402


TEMPLATE = REPOSITORY / "services" / "backend" / "config.template.example.json"


class FakeResponse:
    def __init__(self, url: str, document: dict):
        self.status = 200
        self._url = url
        self._payload = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(self._payload)),
        }

    def geturl(self) -> str:
        return self._url

    def read(self, maximum: int) -> bytes:
        return self._payload[:maximum]

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class FakeOpener:
    def __init__(self, documents: dict[str, dict]):
        self.documents = documents
        self.requests: list[tuple[str, str | None]] = []

    def open(self, request, timeout: int):
        self.assert_timeout = timeout
        url = request.full_url
        self.requests.append((url, request.get_header("Authorization")))
        path = urllib.parse.urlsplit(url).path
        return FakeResponse(url, self.documents[path])


class OperatorToolTests(unittest.TestCase):
    def deployment(self, root: Path) -> tuple[Path, Path, Path]:
        state = root / "state"
        document = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        document["state_directory"] = str(state)
        config_file = root / "config.json"
        config_file.write_text(
            compile_config_template(
                json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2)
                + "\n"
            ),
            encoding="utf-8",
        )
        config_file.chmod(0o600)
        secret_file = root / "admin-secret"
        secret_file.write_bytes(b"operator-test-secret-0123456789abcdef")
        secret_file.chmod(0o600)
        config, secret = load_config(config_file, secret_file)
        PilotBackend(config, secret)
        return config_file, secret_file, state

    @staticmethod
    def add_session(
        state: Path,
        *,
        session_id: str,
        raw_expires_at: str,
        derived_expires_at: str,
        state_value: str = "receiving",
    ) -> None:
        connection = sqlite3.connect(state / "tacua.sqlite3")
        try:
            connection.execute(
                """INSERT INTO sessions(
                       session_id,state,scope_digest,scope_json,
                       build_identity_digest,build_identity_json,created_at,
                       completed_at,raw_media_expires_at,
                       derived_data_expires_at,completion_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    session_id,
                    state_value,
                    "sha256:" + "1" * 64,
                    "{}",
                    "sha256:" + "2" * 64,
                    "{}",
                    "2026-07-22T09:00:00Z",
                    None,
                    raw_expires_at,
                    derived_expires_at,
                    None,
                ),
            )
            connection.commit()
        finally:
            connection.close()

    @staticmethod
    def rewrite_backup_manifest(backup: Path, mutate) -> None:
        path = backup / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        mutate(manifest)
        manifest["backup_digest"] = operator_tool._digest_json(
            manifest,
            "backup_digest",
        )
        path.write_text(
            operator_tool._canonical_json(manifest),
            encoding="utf-8",
        )

    @staticmethod
    def compose_document(
        *,
        immutable: bool,
        state_target: str = "/var/lib/tacua",
        config_source: str = "/deployment/config.json",
        secret_source: str = "/deployment/admin-secret",
    ) -> dict:
        service = {
            "cap_drop": ["ALL"],
            "deploy": {"replicas": 1},
            "image": (
                "registry.example/tacua@sha256:" + "a" * 64
                if immutable
                else "tacua-backend:local"
            ),
            "init": True,
            "logging": {
                "driver": "json-file",
                "options": {"max-file": "3", "max-size": "10m"},
            },
            "networks": {"tacua-default-deny": None},
            "healthcheck": {
                "interval": "30s",
                "retries": 3,
                "start_period": "5s",
                "test": list(operator_tool._COMPOSE_HEALTHCHECK),
                "timeout": "3s",
            },
            "pids_limit": 128,
            "ports": [
                {
                    "host_ip": "127.0.0.1",
                    "target": 8080,
                    "published": "8080",
                    "protocol": "tcp",
                }
            ],
            "read_only": True,
            "restart": "unless-stopped",
            "secrets": [
                {"source": "tacua_admin", "target": "/run/secrets/tacua_admin"}
            ],
            "security_opt": ["no-new-privileges:true"],
            "stop_grace_period": "30s",
            "user": "10001:10001",
            "volumes": [
                {
                    "type": "volume",
                    "source": "tacua-state",
                    "target": state_target,
                },
                {
                    "type": "bind",
                    "source": config_source,
                    "target": "/run/tacua/config.json",
                    "read_only": True,
                },
            ],
        }
        if not immutable:
            service["build"] = {
                "context": "/repository",
                "dockerfile": "services/backend/Dockerfile",
            }
        return {
            "services": {"backend": service},
            "networks": {"tacua-default-deny": {"internal": True}},
            "secrets": {
                "tacua_admin": {
                    "file": secret_source,
                }
            },
        }

    def test_state_lock_allows_one_owner_and_releases_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            with acquire_state_instance_lock(state, create_directory=True):
                with self.assertRaises(InstanceLockError):
                    acquire_state_instance_lock(state, create_directory=False)
                self.assertEqual(0o700, stat.S_IMODE(state.stat().st_mode))
                self.assertEqual(
                    0o600,
                    stat.S_IMODE((state / ".tacua-instance.lock").stat().st_mode),
                )
            with acquire_state_instance_lock(state, create_directory=False):
                pass

    def test_compose_and_preflight_pin_loopback_single_replica_and_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config_file, secret_file, state = self.deployment(Path(temporary))
            config, _secret = load_config(config_file, secret_file)
            immutable = self.compose_document(
                immutable=True,
                state_target=str(state),
                config_source=str(config_file),
                secret_source=str(secret_file),
            )
            result = deployment_preflight(
                config_file,
                secret_file,
                immutable,
                require_immutable_image=True,
                check_state=True,
            )
            self.assertEqual("ok", result["status"])
            self.assertTrue(result["compose"]["immutable_image"])
            self.assertTrue(result["state_checked_offline"])
            self.assertNotIn("operator-test-secret", json.dumps(result))
            self.assertNotIn("admin_secret_digest", result)

            local = self.compose_document(
                immutable=False,
                state_target=str(state),
                config_source=str(config_file),
                secret_source=str(secret_file),
            )
            with self.assertRaises(OperatorError):
                validate_compose_document(
                    local,
                    config,
                    require_immutable_image=True,
                )

            self.assertFalse(
                validate_compose_document(
                    local,
                    config,
                    require_immutable_image=False,
                )["immutable_image"]
            )

            mutations = [
                lambda service: service["deploy"].update(replicas=2),
                lambda service: service["ports"][0].update(host_ip="0.0.0.0"),
                lambda service: service.update(privileged=True),
                lambda service: service.update(cap_add=["NET_ADMIN"]),
                lambda service: service["security_opt"].append(
                    "seccomp=unconfined"
                ),
                lambda service: service["volumes"].append(
                    {
                        "type": "bind",
                        "source": "/var/run/docker.sock",
                        "target": "/var/run/docker.sock",
                    }
                ),
                lambda service: service["logging"].update(options={}),
                lambda service: service["healthcheck"].update(disable=True),
                lambda service: service["healthcheck"].update(
                    test=["CMD", "python", "-c", "print('healthz')"]
                ),
                lambda service: service["ports"][0].update(published="0"),
                lambda service: service.update(networks={"external": None}),
            ]
            for mutate in mutations:
                document = self.compose_document(
                    immutable=True,
                    state_target=str(state),
                    config_source=str(config_file),
                    secret_source=str(secret_file),
                )
                mutate(document["services"]["backend"])
                with self.assertRaises(OperatorError):
                    validate_compose_document(
                        document,
                        config,
                        require_immutable_image=True,
                    )

            document = self.compose_document(
                immutable=True,
                state_target=str(state),
                config_source=str(config_file),
                secret_source=str(secret_file),
            )
            document["networks"]["tacua-default-deny"]["internal"] = False
            with self.assertRaises(OperatorError):
                validate_compose_document(
                    document,
                    config,
                    require_immutable_image=True,
                )

            document = self.compose_document(
                immutable=True,
                state_target=str(state),
                config_source=str(config_file),
                secret_source=str(secret_file),
            )
            document["services"]["backend"]["networks"]["second"] = None
            document["networks"]["second"] = {"internal": True}
            with self.assertRaises(OperatorError):
                validate_compose_document(
                    document,
                    config,
                    require_immutable_image=True,
                )

            document = self.compose_document(
                immutable=True,
                state_target=str(state),
                config_source=str(config_file),
                secret_source=str(secret_file),
            )
            document["services"]["privileged-sidecar"] = {
                "image": "example.invalid/sidecar:latest",
                "privileged": True,
                "volumes_from": ["backend"],
            }
            with self.assertRaisesRegex(OperatorError, "only the backend service"):
                validate_compose_document(
                    document,
                    config,
                    require_immutable_image=True,
                )

    def test_state_preflight_handles_uri_metacharacters_in_the_state_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "deployment?pilot"
            root.mkdir()
            config_file, secret_file, state = self.deployment(root)
            result = deployment_preflight(
                config_file,
                secret_file,
                self.compose_document(
                    immutable=True,
                    state_target=str(state),
                    config_source=str(config_file),
                    secret_source=str(secret_file),
                ),
                require_immutable_image=True,
                check_state=True,
            )
            self.assertTrue(result["state_checked_offline"])

    def test_state_preflight_rejects_a_different_valid_deployment_pin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file, secret_file, state = self.deployment(root)
            document = json.loads(config_file.read_text(encoding="utf-8"))
            document["reviewer_id"] = "reviewer_changed"
            config_file.write_text(
                json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2)
                + "\n",
                encoding="utf-8",
            )
            config_file.chmod(0o600)
            compose = self.compose_document(
                immutable=True,
                state_target=str(state),
                config_source=str(config_file),
                secret_source=str(secret_file),
            )
            with self.assertRaisesRegex(
                OperatorError,
                "state deployment pin differs from the supplied config",
            ):
                deployment_preflight(
                    config_file,
                    secret_file,
                    compose,
                    require_immutable_image=True,
                    check_state=True,
                )

    def test_preflight_rejects_a_group_readable_host_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config_file, secret_file, state = self.deployment(Path(temporary))
            secret_file.chmod(0o640)
            with self.assertRaises(OperatorError):
                deployment_preflight(
                    config_file,
                    secret_file,
                    self.compose_document(
                        immutable=True,
                        state_target=str(state),
                        config_source=str(config_file),
                        secret_source=str(secret_file),
                    ),
                    require_immutable_image=True,
                    check_state=False,
                )

    def test_preflight_rejects_config_that_would_fail_backend_startup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config_file, secret_file, state = self.deployment(Path(temporary))
            document = json.loads(config_file.read_text(encoding="utf-8"))
            document["derived_retention_days"] = document["raw_retention_days"] - 1
            config_file.write_text(
                json.dumps(document, ensure_ascii=False, allow_nan=False),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigError,
                "V1 raw and derived retention periods must use one session boundary",
            ):
                deployment_preflight(
                    config_file,
                    secret_file,
                    self.compose_document(
                        immutable=True,
                        state_target=str(state),
                        config_source=str(config_file),
                        secret_source=str(secret_file),
                    ),
                    require_immutable_image=True,
                    check_state=False,
                )

    def test_offline_backup_verification_and_apply_only_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file, secret_file, _state = self.deployment(root)
            backup = root / "backup"
            manifest = create_backup(config_file, secret_file, backup)
            self.assertEqual("tacua.operator-backup@2.0.0", manifest["contract_version"])
            self.assertEqual(
                {
                    "contract_version": "tacua.operator-backup-evidence-retention@1.0.0",
                    "contains_session_evidence": False,
                    "session_count": 0,
                    "earliest_evidence_expires_at": None,
                },
                manifest["evidence_retention"],
            )
            self.assertEqual(0o700, stat.S_IMODE(backup.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE((backup / "admin-secret").stat().st_mode))
            self.assertFalse((backup / "state" / ".tacua-instance.lock").exists())
            with patch.object(
                operator_tool,
                "_now_utc",
                return_value=datetime(2099, 1, 1, tzinfo=timezone.utc),
            ):
                verified = verify_backup(backup)
            self.assertEqual("ok", verified["status"])
            self.assertEqual(manifest["evidence_retention"], verified["evidence_retention"])

            restored = root / "restored"
            dry_run = restore_backup(backup, restored, apply=False)
            self.assertFalse(dry_run["applied"])
            self.assertFalse(restored.exists())
            applied = restore_backup(backup, restored, apply=True)
            self.assertTrue(applied["applied"])
            self.assertEqual("ok", verify_backup(restored)["status"])
            with self.assertRaises(OperatorError):
                restore_backup(backup, restored, apply=True)

    def test_backup_seals_earliest_session_evidence_deadline_and_refuses_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file, secret_file, state = self.deployment(root)
            self.add_session(
                state,
                session_id="session_later",
                raw_expires_at="2026-07-25T10:00:00Z",
                derived_expires_at="2026-07-25T10:00:00Z",
            )
            self.add_session(
                state,
                session_id="session_earlier",
                raw_expires_at="2026-07-24T10:00:00Z",
                derived_expires_at="2026-07-23T10:00:00Z",
                state_value="deleting",
            )
            before = datetime(2026, 7, 22, 10, 0, 0, tzinfo=timezone.utc)
            backup = root / "backup-retained"
            with patch.object(operator_tool, "_now_utc", return_value=before):
                manifest = create_backup(config_file, secret_file, backup)
            self.assertEqual(
                {
                    "contract_version": "tacua.operator-backup-evidence-retention@1.0.0",
                    "contains_session_evidence": True,
                    "session_count": 2,
                    "earliest_evidence_expires_at": "2026-07-23T10:00:00Z",
                },
                manifest["evidence_retention"],
            )

            before_expiry = datetime(2026, 7, 23, 9, 59, 59, tzinfo=timezone.utc)
            restored = root / "restored-retained"
            with patch.object(
                operator_tool,
                "_now_utc",
                return_value=before_expiry,
            ):
                self.assertEqual("ok", verify_backup(backup)["status"])
                self.assertFalse(
                    restore_backup(backup, root / "dry-run-retained", apply=False)[
                        "applied"
                    ]
                )
                self.assertTrue(restore_backup(backup, restored, apply=True)["applied"])

            deadline = datetime(2026, 7, 23, 10, 0, 0, tzinfo=timezone.utc)
            refused_destination = root / "expired-restore"
            with patch.object(
                operator_tool,
                "_now_utc",
                return_value=deadline,
            ):
                with self.assertRaisesRegex(
                    OperatorError,
                    "evidence retention deadline has expired",
                ):
                    verify_backup(backup)
                with self.assertRaisesRegex(
                    OperatorError,
                    "evidence retention deadline has expired",
                ):
                    restore_backup(backup, root / "expired-dry-run", apply=False)
                with self.assertRaisesRegex(
                    OperatorError,
                    "evidence retention deadline has expired",
                ):
                    restore_backup(backup, refused_destination, apply=True)
            self.assertFalse(refused_destination.exists())

    def test_backup_retention_metadata_is_closed_and_bound_to_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file, secret_file, state = self.deployment(root)
            self.add_session(
                state,
                session_id="session_bound",
                raw_expires_at="2026-08-21T10:00:00Z",
                derived_expires_at="2026-08-21T10:00:00Z",
            )
            now = datetime(2026, 7, 22, 10, 0, 0, tzinfo=timezone.utc)

            mutations = (
                lambda manifest: manifest.update(
                    {"contract_version": "tacua.operator-backup@1.0.0"}
                ),
                lambda manifest: manifest["evidence_retention"].update(
                    {
                        "contract_version": (
                            "tacua.operator-backup-evidence-retention@0.9.0"
                        )
                    }
                ),
                lambda manifest: manifest["evidence_retention"].update(
                    {"unknown": "forbidden"}
                ),
                lambda manifest: manifest["evidence_retention"].update(
                    {"session_count": True}
                ),
                lambda manifest: manifest["evidence_retention"].update(
                    {"earliest_evidence_expires_at": None}
                ),
                lambda manifest: manifest["evidence_retention"].update(
                    {"earliest_evidence_expires_at": "2026-99-99T10:00:00Z"}
                ),
                lambda manifest: manifest["evidence_retention"].update(
                    {"earliest_evidence_expires_at": "2026-08-22T10:00:00Z"}
                ),
            )
            for index, mutation in enumerate(mutations):
                with self.subTest(index=index):
                    backup = root / f"backup-tampered-{index}"
                    with patch.object(operator_tool, "_now_utc", return_value=now):
                        create_backup(config_file, secret_file, backup)
                    self.rewrite_backup_manifest(backup, mutation)
                    with patch.object(operator_tool, "_now_utc", return_value=now):
                        with self.assertRaises(OperatorError):
                            verify_backup(backup)

    def test_expired_or_malformed_session_deadline_prevents_backup_publication(self) -> None:
        cases = (
            ("2026-07-22T10:00:00Z", "2026-07-22T10:00:00Z"),
            ("2026-08-22T10:00:00Z", "not-a-timestamp"),
        )
        for index, (raw_expiry, derived_expiry) in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                config_file, secret_file, state = self.deployment(root)
                self.add_session(
                    state,
                    session_id=f"session_invalid_{index}",
                    raw_expires_at=raw_expiry,
                    derived_expires_at=derived_expiry,
                )
                backup = root / "backup-refused"
                now = datetime(2026, 7, 22, 10, 0, 0, tzinfo=timezone.utc)
                with patch.object(operator_tool, "_now_utc", return_value=now):
                    with self.assertRaises(OperatorError):
                        create_backup(config_file, secret_file, backup)
                self.assertFalse(backup.exists())

    def test_backup_fails_closed_on_live_owner_and_tampered_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file, secret_file, state = self.deployment(root)
            with acquire_state_instance_lock(state, create_directory=False):
                with self.assertRaises(InstanceLockError):
                    create_backup(config_file, secret_file, root / "blocked")
            backup = root / "backup"
            create_backup(config_file, secret_file, backup)
            manifest_path = backup / "manifest.json"
            original_manifest = manifest_path.read_bytes()
            manifest_path.write_bytes(
                b'{"nested":' + b"[" * 2_000 + b"0" + b"]" * 2_000 + b"}"
            )
            with self.assertRaisesRegex(OperatorError, "is not strict JSON"):
                verify_backup(backup)
            manifest_path.write_bytes(original_manifest)
            (backup / "admin-secret").chmod(0o640)
            with self.assertRaises(OperatorError):
                verify_backup(backup)
            (backup / "admin-secret").chmod(0o600)
            database = backup / "state" / "tacua.sqlite3"
            with database.open("ab") as stream:
                stream.write(b"tamper")
            with self.assertRaises(OperatorError):
                verify_backup(backup)

    def test_restore_verifies_staging_before_atomic_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file, secret_file, _state = self.deployment(root)
            backup = root / "backup"
            create_backup(config_file, secret_file, backup)
            destination = root / "restored"
            original_copy = operator_tool._copy_file

            def corrupt_copied_secret(
                source: Path,
                target: Path,
                mode: int,
                *,
                require_service_owner: bool = True,
            ) -> tuple[int, str]:
                copied = original_copy(
                    source,
                    target,
                    mode,
                    require_service_owner=require_service_owner,
                )
                if source == backup / "admin-secret":
                    target.write_bytes(b"changed after source verification")
                return copied

            with patch.object(
                operator_tool,
                "_copy_file",
                side_effect=corrupt_copied_secret,
            ):
                with self.assertRaises(OperatorError):
                    restore_backup(backup, destination, apply=True)

            self.assertFalse(destination.exists())
            self.assertEqual([], list(root.glob(".restored.staging-*")))

    def test_backup_rejects_public_state_permissions_and_mismatched_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file, secret_file, state = self.deployment(root)
            database = state / "tacua.sqlite3"
            database.chmod(0o640)
            with self.assertRaises(OperatorError):
                create_backup(config_file, secret_file, root / "public-state")
            database.chmod(0o600)

            document = json.loads(config_file.read_text(encoding="utf-8"))
            document["reviewer_id"] = "reviewer_changed"
            config_file.write_text(
                json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2)
                + "\n",
                encoding="utf-8",
            )
            config_file.chmod(0o600)
            with self.assertRaises(OperatorError):
                create_backup(config_file, secret_file, root / "wrong-config")

    def test_health_degrades_when_retention_sweep_becomes_stale(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file, secret_file, _state = self.deployment(root)
            config, secret = load_config(config_file, secret_file)
            clock = [datetime.now(timezone.utc).replace(microsecond=0)]
            backend = PilotBackend(config, secret, clock=lambda: clock[0])
            backend.start_retention_enforcement()
            try:
                self.assertEqual("ok", backend.health()["status"])
                clock[0] = clock[0] + timedelta(
                    seconds=2 * config.retention_sweep_interval_seconds + 61
                )
                self.assertEqual("degraded", backend.health()["status"])
            finally:
                backend.stop_retention_enforcement()

    def test_smoke_checks_public_health_retention_and_authenticated_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file, secret_file, _state = self.deployment(root)
            config, secret = load_config(config_file, secret_file)
            swept_at = datetime.now(timezone.utc).replace(microsecond=0).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            opener = FakeOpener(
                {
                    "/version": {
                        "service": "tacua-backend",
                        "version": "0.2.0",
                        "protocol_version": "tacua.sdk-backend@1.0.0",
                    },
                    "/healthz": {
                        "status": "ok",
                        "service": "tacua-backend",
                        "version": "0.2.0",
                        "protocol_version": "tacua.sdk-backend@1.0.0",
                        "schema_version": 2,
                        "sessions": 0,
                        "tombstones": 0,
                        "pending_deletions": 0,
                        "retention_worker_running": True,
                        "retention_last_swept_at": swept_at,
                        "retention_last_deleted_sessions": 0,
                        "retention_last_failed_sessions": 0,
                    },
                    "/v1/admin/builds": {
                        "builds": [
                            {
                                "build_id": config.build_id,
                                "application_id": config.application_id,
                                "bundle_identifier": config.bundle_identifier,
                                "native_version": config.build_identity["native_version"],
                                "native_build": config.build_identity["native_build"],
                                "distribution": config.build_identity["distribution"],
                                "build_identity_digest": config.build_identity_digest,
                            }
                        ]
                    },
                }
            )
            result = smoke_deployment(
                config_file,
                secret_file,
                origin_override="http://127.0.0.1:8080",
                allow_loopback_http=True,
                opener_factory=lambda _context: opener,
            )
            self.assertEqual("ok", result["status"])
            self.assertEqual(
                [None, None, f"Bearer {secret.decode('utf-8')}"],
                [authorization for _url, authorization in opener.requests],
            )

    def test_smoke_rejects_an_unbounded_content_length_without_integer_parsing(self) -> None:
        response = FakeResponse("https://qa.example/version", {"status": "ok"})
        response.headers["Content-Length"] = "9" * 5_000

        class OversizedLengthOpener:
            def open(self, _request, timeout: int):
                self.timeout = timeout
                return response

        with self.assertRaisesRegex(OperatorError, "invalid byte declaration"):
            operator_tool._read_smoke_json(
                OversizedLengthOpener(),
                "https://qa.example/version",
                authorization=None,
            )


if __name__ == "__main__":
    unittest.main()
