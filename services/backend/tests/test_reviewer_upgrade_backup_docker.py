# SPDX-License-Identifier: Apache-2.0
"""No-daemon tests for the exact reviewer-upgrade Docker backup adapter."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "services" / "backend" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import reconcile_compose_deployment as RECONCILER  # noqa: E402
import reviewer_upgrade_backup as BACKUP  # noqa: E402
import reviewer_upgrade_backup_docker as DOCKER_BACKUP  # noqa: E402
import reviewer_upgrade_journal as JOURNAL  # noqa: E402


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class FakeDocker:
    def __init__(
        self,
        backend_document: list[dict],
        bindings: BACKUP.BackupBindings,
    ) -> None:
        self.backend_document = deepcopy(backend_document)
        self.bindings = bindings
        self.calls: list[tuple[list[str], int]] = []
        self.auxiliaries: dict[str, list[dict]] = {}
        self.wrong_verify_digest: str | None = None
        self.empty_state_file = True

    def _mount_source(self, argv: list[str], destination: str) -> Path:
        for index, item in enumerate(argv):
            if item != "--mount":
                continue
            options = argv[index + 1].split(",")
            values = {
                key: value
                for key, value in (
                    option.split("=", 1)
                    for option in options
                    if "=" in option
                )
            }
            if values.get("dst") == destination:
                return Path(values["src"])
        raise AssertionError((destination, argv))

    def _write_bundle(self, output: Path) -> None:
        output.mkdir(mode=0o700)
        state = output / "state"
        state.mkdir(mode=0o700)
        payloads = {
            "admin-secret": b"synthetic-secret\n",
            "config.json": b'{"pilot":true}\n',
            "state/database.sqlite3": b"" if self.empty_state_file else b"db\n",
        }
        records = []
        for relative, payload in sorted(payloads.items()):
            path = output / relative
            path.write_bytes(payload)
            path.chmod(0o600)
            records.append({
                "content_digest": _digest(payload),
                "path": relative,
                "size_bytes": len(payload),
            })
        manifest = {
            "backend_version": "0.1.0",
            "backup_digest": "",
            "configured_state_directory": str(
                self.bindings.source_state_directory
            ),
            "contract_version": DOCKER_BACKUP.BACKUP_OPERATOR_CONTRACT,
            "created_at": "2026-08-04T12:00:00Z",
            "deployment_pin_digest": "sha256:" + "8" * 64,
            "directories": ["state"],
            "evidence_retention": {
                "contract_version": "synthetic-retention@1",
            },
            "files": records,
            "protocol_version": "1",
            "state_file_count": 1,
            "state_total_bytes": len(payloads["state/database.sqlite3"]),
        }
        manifest["backup_digest"] = _digest(
            DOCKER_BACKUP._operator_canonical(
                manifest,
                "backup_digest",
            )
        )
        manifest_path = output / DOCKER_BACKUP.BACKUP_MANIFEST_FILE
        manifest_path.write_bytes(
            DOCKER_BACKUP._operator_canonical(manifest)
        )
        manifest_path.chmod(0o600)

    def _verify_output(self, bundle: Path) -> bytes:
        manifest = json.loads(
            (bundle / DOCKER_BACKUP.BACKUP_MANIFEST_FILE).read_text(
                encoding="utf-8"
            )
        )
        result = {
            "backup_digest": (
                self.wrong_verify_digest or manifest["backup_digest"]
            ),
            "contract_version": DOCKER_BACKUP.BACKUP_OPERATOR_CONTRACT,
            "created_at": manifest["created_at"],
            "evidence_retention": manifest["evidence_retention"],
            "state_file_count": manifest["state_file_count"],
            "state_total_bytes": manifest["state_total_bytes"],
            "status": "ok",
        }
        return DOCKER_BACKUP._operator_canonical(result) + b"\n"

    def add_orphan(
        self,
        adapter: DOCKER_BACKUP.DockerBackupRunner,
        *,
        number: int,
        role: str,
        status: str = "running",
    ) -> str:
        identifier = "9" * 64
        name = adapter._auxiliary_name(number, role)
        entrypoint, command = adapter._expected_auxiliary_command(role)
        bundle = (
            adapter.transaction
            / f"backup-attempt-{number:02d}"
            / BACKUP.BACKUP_BUNDLE_DIRECTORY
        )
        mounts = list(
            adapter._expected_auxiliary_mounts(role, bundle).values()
        )
        mounts.append({
            "Destination": "/tmp",
            "Name": "",
            "RW": True,
            "Source": "",
            "Type": "tmpfs",
        })
        self.auxiliaries[identifier] = [{
            "Config": {
                "Cmd": command,
                "Entrypoint": entrypoint,
                "Env": ["TMPDIR=/tmp"],
                "Healthcheck": {"Test": ["NONE"]},
                "Image": adapter.bindings.backend_image_id,
                "Labels": adapter._auxiliary_labels(number, role),
                "User": "10001:10001" if role == "archive" else "0:0",
            },
            "HostConfig": {
                "AutoRemove": True,
                "CapAdd": (
                    [
                        "CAP_CHOWN",
                        "CAP_DAC_READ_SEARCH",
                        "CAP_FOWNER",
                    ]
                    if role == "normalize"
                    else ["CAP_CHOWN", "CAP_FOWNER"]
                    if role == "prepare"
                    else None
                ),
                "CapDrop": ["ALL"],
                "Init": True,
                "IpcMode": "none",
                "LogConfig": {"Config": {}, "Type": "none"},
                "Memory": 536_870_912,
                "MemorySwap": 536_870_912,
                "NanoCpus": 1_000_000_000,
                "NetworkMode": "none",
                "PidsLimit": 128,
                "PortBindings": {},
                "Privileged": False,
                "PublishAllPorts": False,
                "ReadonlyRootfs": True,
                "RestartPolicy": {
                    "MaximumRetryCount": 0,
                    "Name": "no",
                },
                "SecurityOpt": ["no-new-privileges:true"],
                "Tmpfs": {
                    "/tmp": (
                        "rw,nosuid,nodev,noexec,size=67108864,"
                        f"uid={'10001' if role == 'archive' else '0'},"
                        f"gid={'10001' if role == 'archive' else '0'},"
                        "mode=0700"
                    )
                },
            },
            "Id": identifier,
            "Image": adapter.bindings.backend_image_id,
            "Mounts": mounts,
            "Name": "/" + name,
            "State": {
                "Running": status == "running",
                "Status": status,
            },
        }]
        return identifier

    def __call__(self, raw_argv: list[str], *, timeout: int) -> bytes:
        argv = list(raw_argv)
        self.calls.append((argv, timeout))
        if "compose" in argv and "ps" in argv:
            return (self.bindings.backend_container_id + "\n").encode("ascii")
        if argv[-5:-2] == ["image", "inspect", "--format"]:
            return (self.bindings.backend_image_id + "\n").encode("ascii")
        if "container" in argv and "ls" in argv:
            selected: list[str] = []
            filter_value = argv[argv.index("--filter") + 1]
            if filter_value.startswith("volume="):
                selected = [self.bindings.backend_container_id]
                selected.extend(
                    identifier
                    for identifier, document in self.auxiliaries.items()
                    if any(
                        mount.get("Destination") == "/var/lib/tacua"
                        for mount in document[0]["Mounts"]
                    )
                )
            elif filter_value.startswith("label="):
                selected = list(self.auxiliaries)
            elif filter_value.startswith("name="):
                prefix = filter_value.removeprefix("name=")
                selected = [
                    identifier
                    for identifier, document in self.auxiliaries.items()
                    if prefix in document[0]["Name"]
                ]
            return ("\n".join(sorted(selected)) + ("\n" if selected else "")).encode(
                "ascii"
            )
        if argv[-3:-1] == ["container", "inspect"]:
            identifier = argv[-1]
            if identifier == self.bindings.backend_container_id:
                return json.dumps(self.backend_document).encode("ascii")
            return json.dumps(self.auxiliaries[identifier]).encode("ascii")
        if "container" in argv and "stop" in argv:
            identifier = argv[-1]
            if identifier == self.bindings.backend_container_id:
                state = self.backend_document[0]["State"]
                state.clear()
                state.update({
                    "Health": {"Status": "unhealthy"},
                    "Running": False,
                    "Status": "exited",
                })
                for network in self.backend_document[0][
                    "NetworkSettings"
                ]["Networks"].values():
                    network.update({
                        "EndpointID": "",
                        "Gateway": "",
                        "IPAddress": "",
                        "MacAddress": "",
                    })
            else:
                if self.auxiliaries[identifier][0]["HostConfig"]["AutoRemove"]:
                    self.auxiliaries.pop(identifier)
                else:
                    self.auxiliaries[identifier][0]["State"] = {
                        "Running": False,
                        "Status": "exited",
                    }
            return (identifier + "\n").encode("ascii")
        if "container" in argv and "start" in argv:
            identifier = argv[-1]
            state = self.backend_document[0]["State"]
            state.clear()
            state.update({
                "Health": {"Status": "healthy"},
                "Running": True,
                "Status": "running",
            })
            return (identifier + "\n").encode("ascii")
        if "container" in argv and "rm" in argv:
            identifier = argv[-1]
            self.auxiliaries.pop(identifier)
            return (identifier + "\n").encode("ascii")
        if "run" in argv:
            labels = [
                argv[index + 1]
                for index, value in enumerate(argv)
                if value == "--label"
            ]
            role_label = next(
                value
                for value in labels
                if value.startswith(
                    DOCKER_BACKUP._AUX_LABEL_PREFIX + "role="
                )
            )
            role = role_label.rsplit("=", 1)[1]
            bundle = self._mount_source(argv, "/backup")
            if role == "archive":
                self._write_bundle(
                    bundle / DOCKER_BACKUP.BACKUP_OUTPUT_DIRECTORY
                )
                return b""
            if role == "normalize":
                for path in bundle.rglob("*"):
                    path.chmod(0o700 if path.is_dir() else 0o600)
                bundle.chmod(0o700)
                return b""
            if role == "verify":
                return self._verify_output(bundle)
            return b""
        raise AssertionError(argv)


class ReviewerUpgradeDockerBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.config = self.root / "config.json"
        self.config.write_bytes(b'{"pilot":true}\n')
        self.config.chmod(0o644)
        self.secret = self.root / "admin-secret"
        self.secret.write_bytes(b"synthetic-secret\n")
        self.secret.chmod(0o444)
        self.operation_id = "reviewer-20260804-adapter"
        self.image_id = "sha256:" + "b" * 64
        self.container_id = "a" * 64
        self.state_volume = "tacua_tacua-state"
        self.backend_document = self._backend_document()
        self.source, self.manifest, self.compose = self._sealed_state(
            desired="maintenance"
        )
        upgrades = self.source.parent / "upgrades"
        upgrades.mkdir(mode=0o700)
        self.transaction = JOURNAL.create_transaction_directory(
            upgrades / self.operation_id
        )
        self.bindings = BACKUP.validate_backup_bindings(
            self._bindings_document()
        )
        self.fake = FakeDocker(self.backend_document, self.bindings)
        self.smoke_calls: list[tuple[Path, Path, str]] = []
        self.adapter = DOCKER_BACKUP.create_docker_backup_runner(
            self.transaction,
            self.bindings,
            self.manifest,
            self.compose,
            self.fake,
            smoke_runner=lambda config, secret, origin: self.smoke_calls.append(
                (config, secret, origin)
            ),
        )

    def _backend_document(self) -> list[dict]:
        return [{
            "Config": {
                "Healthcheck": {"Test": ["CMD", "true"]},
                "Image": "tacua-backend:adapter-test",
                "Labels": {
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "tacua",
                    "com.docker.compose.service": "backend",
                },
                "User": "10001:10001",
            },
            "HostConfig": {
                "AutoRemove": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "DeviceRequests": None,
                "Devices": None,
                "Init": True,
                "LogConfig": {
                    "Config": {"max-file": "3", "max-size": "10m"},
                    "Type": "json-file",
                },
                "NetworkMode": "tacua_private",
                "PidsLimit": 128,
                "PortBindings": {},
                "Privileged": False,
                "PublishAllPorts": False,
                "ReadonlyRootfs": True,
                "RestartPolicy": {
                    "MaximumRetryCount": 0,
                    "Name": "unless-stopped",
                },
                "SecurityOpt": ["no-new-privileges:true"],
            },
            "Id": self.container_id,
            "Image": self.image_id,
            "Mounts": [{
                "Destination": "/var/lib/tacua",
                "Name": self.state_volume,
                "Propagation": "",
                "RW": True,
                "Source": "/private/docker/tacua-state/_data",
                "Type": "volume",
            }],
            "Name": "/tacua-backend-1",
            "NetworkSettings": {
                "Networks": {
                    "tacua_private": {
                        "Aliases": ["backend", "tacua-backend-1"],
                        "EndpointID": "e" * 64,
                        "Gateway": "172.28.0.1",
                        "IPAddress": "172.28.0.2",
                        "MacAddress": "02:42:ac:1c:00:02",
                        "NetworkID": "d" * 64,
                    },
                },
            },
            "State": {
                "Health": {"Status": "healthy"},
                "Running": True,
                "Status": "running",
            },
        }]

    def _sealed_state(
        self,
        *,
        desired: str,
    ) -> tuple[Path, dict, Path]:
        source = self.root / "state"
        source.mkdir(mode=0o700)
        generations = source / "generations"
        generations.mkdir(mode=0o700)
        generation = generations / "generation-1"
        generation.mkdir(mode=0o700)
        compose_document = {
            "name": "tacua",
            "services": {
                "backend": {"image": "tacua-backend:adapter-test"},
            },
            "volumes": {
                "tacua-state": {"name": self.state_volume},
            },
        }
        compose_payload = RECONCILER._canonical(compose_document)
        compose = generation / RECONCILER.COMPOSE_FILE
        compose.write_bytes(compose_payload)
        compose.chmod(0o400)
        backend_projection = RECONCILER._container_projection(
            self.backend_document,
            project="tacua",
            service="backend",
            published_port=8080,
        )
        operation = self.root / "operations"
        operation.mkdir(mode=0o700)
        manifest = {
            "commands": {
                "docker": "/usr/bin/docker",
                "docker_service": "docker.service",
                "systemctl": "/usr/bin/systemctl",
                "tailscale": "/usr/bin/tailscale",
            },
            "compose_digest": _digest(compose_payload),
            "config": RECONCILER._identity(self.config, secret=False),
            "containers": {
                "backend": backend_projection,
                "ingress": {},
                "reviewer": {},
            },
            "contract_version": RECONCILER.GENERATION_CONTRACT,
            "daemon": {
                "cgroup_driver": "systemd",
                "cgroup_version": "2",
                "docker_root_directory": "/private/docker",
                "id": "synthetic-rootless-daemon",
                "security_options": ["name=rootless"],
            },
            "generation": "generation-1",
            "manifest_digest": "",
            "operation_directory": str(operation),
            "project": "tacua",
            "published_port": 8080,
            "resources": {"networks": {}, "volumes": {}},
            "runtime": {
                "docker_host": "unix:///run/user/501/docker.sock",
                "home": str(self.root),
                "xdg_runtime_directory": "/run/user/501",
            },
            "secret": RECONCILER._identity(self.secret, secret=True),
        }
        manifest["manifest_digest"] = RECONCILER._document_digest(
            manifest,
            "manifest_digest",
        )
        manifest_path = generation / RECONCILER.MANIFEST_FILE
        manifest_path.write_bytes(RECONCILER._canonical(manifest))
        manifest_path.chmod(0o600)
        desired_document = {
            "compose_digest": manifest["compose_digest"],
            "contract_version": RECONCILER.DESIRED_CONTRACT,
            "desired": desired,
            "generation": manifest["generation"],
            "manifest_digest": manifest["manifest_digest"],
            "project": manifest["project"],
            "state_digest": "",
        }
        desired_document["state_digest"] = RECONCILER._document_digest(
            desired_document,
            "state_digest",
        )
        desired_path = source / RECONCILER.DESIRED_FILE
        desired_path.write_bytes(RECONCILER._canonical(desired_document))
        desired_path.chmod(0o600)
        loaded_desired, loaded_manifest, loaded_compose = (
            RECONCILER._load_bound_state(source)
        )
        self.assertEqual(loaded_desired, desired_document)
        return source, loaded_manifest, loaded_compose

    def _bindings_document(self) -> dict:
        return {
            "backend": {
                "container_id": self.container_id,
                "image_id": self.image_id,
                "image_ref": "tacua-backend:adapter-test",
                "state_volume": self.state_volume,
            },
            "config": self.manifest["config"],
            "contract_version": BACKUP.BACKUP_BINDINGS_CONTRACT,
            "operation_id": self.operation_id,
            "plan_digest": "sha256:" + "c" * 64,
            "project": "tacua",
            "secret": self.manifest["secret"],
            "source": {
                "compose_digest": self.manifest["compose_digest"],
                "generation": self.manifest["generation"],
                "manifest_digest": self.manifest["manifest_digest"],
                "state_directory": str(self.source),
            },
        }

    def _run_backup(self) -> dict:
        return BACKUP.run_backup_attempt(
            self.transaction,
            self.bindings,
            self.adapter,
            health_attempts=2,
            health_interval_seconds=0,
            sleeper=lambda _seconds: None,
        )

    def _post_stop_index_runner(
        self,
        gate: str,
        failures: int,
    ) -> tuple[Callable[..., bytes], dict[str, int]]:
        self.assertIn(gate, {"compose", "volume"})
        stats = {"failed": 0, "remaining": failures}

        def command_runner(
            raw_argv: list[str],
            *,
            timeout: int,
        ) -> bytes:
            argv = list(raw_argv)
            stopped = (
                self.fake.backend_document[0]["State"]["Status"] == "exited"
            )
            selected = (
                gate == "compose" and "compose" in argv and "ps" in argv
            ) or (
                gate == "volume"
                and "container" in argv
                and "ls" in argv
                and f"volume={self.state_volume}" in argv
            )
            if stopped and selected and stats["remaining"]:
                stats["failed"] += 1
                stats["remaining"] -= 1
                return b""
            return self.fake(argv, timeout=timeout)

        return command_runner, stats

    def _assert_backup_retries_second_post_stop_observation(
        self,
        gate: str,
    ) -> None:
        command_runner, stats = self._post_stop_index_runner(gate, 1)
        armed = False

        def gated_command_runner(
            raw_argv: list[str],
            *,
            timeout: int,
        ) -> bytes:
            if not armed:
                return self.fake(raw_argv, timeout=timeout)
            return command_runner(raw_argv, timeout=timeout)

        self.adapter.command_runner = gated_command_runner

        def runner(action: str, request: dict) -> dict:
            nonlocal armed
            result = self.adapter(action, request)
            if action == "stop_backend":
                armed = True
            return result

        with mock.patch.object(DOCKER_BACKUP.time, "sleep") as sleeper:
            receipt = BACKUP.run_backup_attempt(
                self.transaction,
                self.bindings,
                runner,
                health_attempts=2,
                health_interval_seconds=0,
                sleeper=lambda _seconds: None,
            )

        self.assertEqual(receipt["status"], "backup_ready")
        self.assertEqual(stats, {"failed": 1, "remaining": 0})
        sleeper.assert_called_once_with(
            DOCKER_BACKUP._POST_ACTION_INSPECTION_INTERVAL_SECONDS,
        )

    def _post_start_index_runner(
        self,
        gate: str,
        failures: int,
        *,
        arm_on_start_command: bool,
    ) -> tuple[Callable[..., bytes], dict[str, int | bool]]:
        self.assertIn(gate, {"compose", "volume"})
        stats: dict[str, int | bool] = {
            "armed": False,
            "failed": 0,
            "remaining": failures,
        }

        def command_runner(
            raw_argv: list[str],
            *,
            timeout: int,
        ) -> bytes:
            argv = list(raw_argv)
            selected = (
                gate == "compose" and "compose" in argv and "ps" in argv
            ) or (
                gate == "volume"
                and "container" in argv
                and "ls" in argv
                and f"volume={self.state_volume}" in argv
            )
            if stats["armed"] and selected and stats["remaining"]:
                stats["armed"] = False
                stats["failed"] = int(stats["failed"]) + 1
                stats["remaining"] = int(stats["remaining"]) - 1
                return b""
            payload = self.fake(argv, timeout=timeout)
            if (
                arm_on_start_command
                and "container" in argv
                and "start" in argv
                and argv[-1] == self.container_id
            ):
                stats["armed"] = True
            return payload

        return command_runner, stats

    def _assert_backup_retries_second_post_start_observation(
        self,
        gate: str,
    ) -> None:
        command_runner, stats = self._post_start_index_runner(
            gate,
            1,
            arm_on_start_command=False,
        )
        self.adapter.command_runner = command_runner

        def runner(action: str, request: dict) -> dict:
            result = self.adapter(action, request)
            if action == "start_backend":
                stats["armed"] = True
            return result

        with mock.patch.object(DOCKER_BACKUP.time, "sleep") as sleeper:
            receipt = BACKUP.run_backup_attempt(
                self.transaction,
                self.bindings,
                runner,
                health_attempts=2,
                health_interval_seconds=0,
                sleeper=lambda _seconds: None,
            )

        self.assertEqual(receipt["status"], "backup_ready")
        self.assertEqual(
            stats,
            {"armed": False, "failed": 1, "remaining": 0},
        )
        sleeper.assert_called_once_with(
            DOCKER_BACKUP._POST_ACTION_INSPECTION_INTERVAL_SECONDS,
        )

    def test_full_sealed_manifest_runs_all_actions_without_live_docker(self) -> None:
        receipt = self._run_backup()

        self.assertEqual(receipt["status"], "backup_ready")
        self.assertRegex(receipt["bundle"]["sha256"], r"^sha256:[a-f0-9]{64}$")
        self.assertEqual(self.smoke_calls, [
            (
                self.config,
                self.secret,
                "http://127.0.0.1:8080",
            )
        ])
        auxiliary_runs = [
            argv for argv, _timeout in self.fake.calls if "run" in argv
        ]
        self.assertTrue(auxiliary_runs)
        for argv in auxiliary_runs:
            self.assertIn("--name", argv)
            self.assertEqual(argv.count("--label"), 4)
            self.assertIn("--pull", argv)
            self.assertIn("never", argv)
        bundle = self.transaction / "backup-attempt-01" / "bundle"
        self.assertEqual(
            DOCKER_BACKUP._derive_bundle_digest(bundle),
            receipt["bundle"]["sha256"],
        )
        self.assertEqual((bundle / "state/database.sqlite3").stat().st_size, 0)

    def test_post_stop_attestation_retries_transient_index_drift(self) -> None:
        for gate in ("compose", "volume"):
            with self.subTest(gate=gate):
                self.fake.backend_document = deepcopy(self.backend_document)
                self.fake.calls.clear()
                self.adapter.command_runner, stats = (
                    self._post_stop_index_runner(gate, 1)
                )
                with mock.patch.object(
                    DOCKER_BACKUP.time,
                    "sleep",
                ) as sleeper:
                    result = self.adapter(
                        "stop_backend",
                        {"container_id": self.container_id},
                    )

                self.assertEqual(result["status"], "stopped")
                backend_stop = next(
                    argv
                    for argv, _timeout in self.fake.calls
                    if argv[-5:]
                    == [
                        "container",
                        "stop",
                        "--timeout",
                        "30",
                        self.container_id,
                    ]
                )
                self.assertNotIn("--time", backend_stop)
                self.assertEqual(stats, {"failed": 1, "remaining": 0})
                sleeper.assert_called_once_with(
                    DOCKER_BACKUP._POST_ACTION_INSPECTION_INTERVAL_SECONDS,
                )

    def test_backup_retries_second_post_stop_compose_observation(self) -> None:
        self._assert_backup_retries_second_post_stop_observation("compose")

    def test_backup_retries_second_post_stop_volume_observation(self) -> None:
        self._assert_backup_retries_second_post_stop_observation("volume")

    def test_post_start_attestation_retries_transient_index_drift(self) -> None:
        for gate in ("compose", "volume"):
            with self.subTest(gate=gate):
                self.fake.backend_document = deepcopy(self.backend_document)
                self.fake.backend_document[0]["State"] = {
                    "Health": {"Status": "unhealthy"},
                    "Running": False,
                    "Status": "exited",
                }
                self.adapter.command_runner, stats = self._post_start_index_runner(
                    gate,
                    1,
                    arm_on_start_command=True,
                )
                with mock.patch.object(
                    DOCKER_BACKUP.time,
                    "sleep",
                ) as sleeper:
                    result = self.adapter(
                        "start_backend",
                        {"container_id": self.container_id},
                    )

                self.assertEqual(result["status"], "started")
                self.assertEqual(
                    stats,
                    {"armed": False, "failed": 1, "remaining": 0},
                )
                sleeper.assert_called_once_with(
                    DOCKER_BACKUP._POST_ACTION_INSPECTION_INTERVAL_SECONDS,
                )

    def test_backup_retries_second_post_start_compose_observation(self) -> None:
        self._assert_backup_retries_second_post_start_observation("compose")

    def test_backup_retries_second_post_start_volume_observation(self) -> None:
        self._assert_backup_retries_second_post_start_observation("volume")

    def test_persistent_post_stop_index_failure_recovers_without_bundle(
        self,
    ) -> None:
        attempts = DOCKER_BACKUP._POST_ACTION_INSPECTION_ATTEMPTS
        self.adapter.command_runner, stats = self._post_stop_index_runner(
            "compose",
            attempts,
        )
        with mock.patch.object(DOCKER_BACKUP.time, "sleep") as sleeper:
            with self.assertRaisesRegex(
                BACKUP.BackupError,
                "^REVIEWER_UPGRADE_BACKUP_FAILED$",
            ):
                self._run_backup()

        quarantine = self.transaction / "backup-quarantine-01"
        self.assertEqual(stats, {"failed": attempts, "remaining": 0})
        self.assertEqual(sleeper.call_count, attempts - 1)
        self.assertTrue(quarantine.is_dir())
        self.assertFalse((quarantine / "bundle").exists())
        self.assertFalse(
            any("run" in argv for argv, _timeout in self.fake.calls)
        )
        self.assertEqual(
            self.fake.backend_document[0]["State"],
            {
                "Health": {"Status": "healthy"},
                "Running": True,
                "Status": "running",
            },
        )

    def test_post_stop_attestation_does_not_retry_invalid_state(self) -> None:
        with (
            mock.patch.object(
                self.adapter,
                "_inspect_backend",
                side_effect=DOCKER_BACKUP.DockerBackupError(
                    DOCKER_BACKUP._ERROR,
                ),
            ) as inspect_backend,
            mock.patch.object(DOCKER_BACKUP.time, "sleep") as sleeper,
        ):
            with self.assertRaisesRegex(
                DOCKER_BACKUP.DockerBackupError,
                "^REVIEWER_UPGRADE_BACKUP_DOCKER_INVALID$",
            ):
                self.adapter._inspect_stopped_backend()

        inspect_backend.assert_called_once_with(classify_index_miss=True)
        sleeper.assert_not_called()

    def test_post_action_attestation_does_not_retry_invariant_violations(
        self,
    ) -> None:
        wrong_projection = deepcopy(self.backend_document)
        wrong_projection[0]["Config"]["Image"] = "tacua-backend:drift"
        wrong_status = deepcopy(self.backend_document)
        wrong_status[0]["State"] = {
            "Health": {"Status": "unhealthy"},
            "Running": False,
            "Status": "exited",
        }
        wrong_health = deepcopy(self.backend_document)
        wrong_health[0]["State"]["Health"] = {"Status": "corrupt"}

        def compose(argv: list[str]) -> bool:
            return "compose" in argv and "ps" in argv

        def image(argv: list[str]) -> bool:
            return argv[-5:-2] == ["image", "inspect", "--format"]

        def volume(argv: list[str]) -> bool:
            return (
                "container" in argv
                and "ls" in argv
                and f"volume={self.state_volume}" in argv
            )

        def inspect(argv: list[str]) -> bool:
            return argv[-3:-1] == ["container", "inspect"]

        cases: list[
            tuple[str, Callable[[list[str]], bool], bytes | BaseException]
        ] = [
            (
                "command_failure",
                compose,
                RECONCILER.ReconcileError("RECONCILE_COMMAND_FAILED"),
            ),
            ("newline_only", compose, b"\n"),
            ("wrong_compose_id", compose, b"9" * 64 + b"\n"),
            ("wrong_image_id", image, b"9" * 64 + b"\n"),
            ("wrong_volume_id", volume, b"9" * 64 + b"\n"),
            ("malformed_inspect", inspect, b"{"),
            (
                "projection_drift",
                inspect,
                json.dumps(wrong_projection).encode("ascii"),
            ),
            (
                "unexpected_status",
                inspect,
                json.dumps(wrong_status).encode("ascii"),
            ),
            (
                "invalid_health",
                inspect,
                json.dumps(wrong_health).encode("ascii"),
            ),
        ]
        for name, selected, replacement in cases:
            with self.subTest(name=name):
                hits = 0

                def command_runner(
                    raw_argv: list[str],
                    *,
                    timeout: int,
                ) -> bytes:
                    nonlocal hits
                    argv = list(raw_argv)
                    if selected(argv) and hits == 0:
                        hits += 1
                        if isinstance(replacement, BaseException):
                            raise replacement
                        return replacement
                    return self.fake(argv, timeout=timeout)

                self.adapter.command_runner = command_runner
                with mock.patch.object(
                    DOCKER_BACKUP.time,
                    "sleep",
                ) as sleeper:
                    with self.assertRaisesRegex(
                        DOCKER_BACKUP.DockerBackupError,
                        "^REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED$",
                    ):
                        self.adapter._inspect_backend_in_statuses(
                            frozenset({"running"})
                        )

                self.assertEqual(hits, 1)
                sleeper.assert_not_called()

    def test_transient_index_miss_then_invariant_violation_stops_immediately(
        self,
    ) -> None:
        observations = 0

        def command_runner(
            raw_argv: list[str],
            *,
            timeout: int,
        ) -> bytes:
            nonlocal observations
            argv = list(raw_argv)
            if "compose" in argv and "ps" in argv:
                observations += 1
                if observations == 1:
                    return b""
                if observations == 2:
                    return b"9" * 64 + b"\n"
            return self.fake(argv, timeout=timeout)

        self.adapter.command_runner = command_runner
        with mock.patch.object(DOCKER_BACKUP.time, "sleep") as sleeper:
            with self.assertRaisesRegex(
                DOCKER_BACKUP.DockerBackupError,
                "^REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED$",
            ):
                self.adapter._inspect_started_backend()

        self.assertEqual(observations, 2)
        sleeper.assert_called_once_with(
            DOCKER_BACKUP._POST_ACTION_INSPECTION_INTERVAL_SECONDS,
        )

    def test_persistent_public_post_action_index_failure_is_bounded_and_consumed(
        self,
    ) -> None:
        attempts = DOCKER_BACKUP._POST_ACTION_INSPECTION_ATTEMPTS
        for action in ("stop_backend", "start_backend"):
            with self.subTest(action=action):
                self.fake.backend_document = deepcopy(self.backend_document)
                if action == "start_backend":
                    self.fake.backend_document[0]["State"] = {
                        "Health": {"Status": "unhealthy"},
                        "Running": False,
                        "Status": "exited",
                    }
                self.fake.calls.clear()
                self.adapter.command_runner = self.fake
                self.adapter._post_stop_inspection_pending = False
                self.adapter._post_start_inspection_pending = False
                self.adapter(
                    action,
                    {"container_id": self.container_id},
                )

                observations = 0

                def persistent_index_miss(
                    raw_argv: list[str],
                    *,
                    timeout: int,
                ) -> bytes:
                    nonlocal observations
                    argv = list(raw_argv)
                    if "compose" in argv and "ps" in argv:
                        observations += 1
                        return b""
                    return self.fake(argv, timeout=timeout)

                self.adapter.command_runner = persistent_index_miss
                with mock.patch.object(
                    DOCKER_BACKUP.time,
                    "sleep",
                ) as sleeper:
                    with self.assertRaisesRegex(
                        DOCKER_BACKUP.DockerBackupError,
                        "^REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED$",
                    ):
                        self.adapter(
                            "inspect_backend",
                            self.adapter._backend_request(),
                        )

                self.assertEqual(observations, attempts)
                self.assertEqual(sleeper.call_count, attempts - 1)
                self.assertFalse(self.adapter._post_stop_inspection_pending)
                self.assertFalse(self.adapter._post_start_inspection_pending)
                mutations = [
                    argv
                    for argv, _timeout in self.fake.calls
                    if "container" in argv
                    and any(item in argv for item in ("stop", "start"))
                    and argv[-1] == self.container_id
                ]
                self.assertEqual(len(mutations), 1)

                with mock.patch.object(
                    DOCKER_BACKUP.time,
                    "sleep",
                ) as ordinary_sleeper:
                    with self.assertRaisesRegex(
                        DOCKER_BACKUP.DockerBackupError,
                        "^REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED$",
                    ):
                        self.adapter(
                            "inspect_backend",
                            self.adapter._backend_request(),
                        )
                self.assertEqual(observations, attempts + 1)
                ordinary_sleeper.assert_not_called()

    def test_running_desired_state_is_rejected_before_any_command(self) -> None:
        desired_path = self.source / RECONCILER.DESIRED_FILE
        desired = json.loads(desired_path.read_text(encoding="ascii"))
        desired["desired"] = "running"
        desired["state_digest"] = RECONCILER._document_digest(
            desired,
            "state_digest",
        )
        desired_path.write_bytes(RECONCILER._canonical(desired))
        desired_path.chmod(0o600)

        with self.assertRaisesRegex(
            DOCKER_BACKUP.DockerBackupError,
            "^REVIEWER_UPGRADE_BACKUP_DOCKER_INVALID$",
        ):
            DOCKER_BACKUP.create_docker_backup_runner(
                self.transaction,
                self.bindings,
                self.manifest,
                self.compose,
                self.fake,
                smoke_runner=lambda *_args: None,
            )
        self.assertEqual(self.fake.calls, [])

    def test_enriched_manifest_file_records_use_the_exact_five_key_projection(self) -> None:
        desired, _manifest, compose = RECONCILER._load_bound_state(self.source)
        enriched = deepcopy(self.manifest)
        for key in ("config", "secret"):
            metadata = Path(enriched[key]["path"]).stat()
            enriched[key]["device"] = metadata.st_dev
            enriched[key]["inode"] = metadata.st_ino

        adapter = DOCKER_BACKUP.DockerBackupRunner(
            self.transaction,
            self.bindings,
            enriched,
            self.compose,
            self.fake,
            smoke_runner=lambda *_args: None,
            state_loader=lambda _source: (desired, deepcopy(enriched), compose),
        )

        self.assertEqual(adapter.bindings, self.bindings)
        self.assertEqual(self.fake.calls, [])

    def test_wrong_operator_digest_is_rejected(self) -> None:
        receipt = self._run_backup()
        self.fake.wrong_verify_digest = "sha256:" + "0" * 64
        request = self.adapter._attempt_request(1)

        with self.assertRaisesRegex(
            DOCKER_BACKUP.DockerBackupError,
            "^REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED$",
        ):
            self.adapter("verify_backup", request)
        self.assertTrue(receipt["bundle"]["verified"])

    def test_mutation_between_verify_and_fsync_is_rejected(self) -> None:
        receipt = self._run_backup()
        bundle = self.transaction / "backup-attempt-01" / "bundle"
        database = bundle / "state/database.sqlite3"
        database.write_bytes(b"mutated\n")
        database.chmod(0o600)
        request = self.adapter._attempt_request(
            1,
            bundle_digest=receipt["bundle"]["sha256"],
        )

        with self.assertRaisesRegex(
            DOCKER_BACKUP.DockerBackupError,
            "^REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED$",
        ):
            self.adapter("fsync_backup", request)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires POSIX")
    def test_fifo_swap_at_fsync_boundary_is_nonblocking_and_rejected(self) -> None:
        receipt = self._run_backup()
        bundle = self.transaction / "backup-attempt-01" / "bundle"
        database = bundle / "state/database.sqlite3"
        real_fsync = DOCKER_BACKUP._fsync_bundle

        def replace_with_fifo(path: Path) -> None:
            database.unlink()
            os.mkfifo(database, 0o600)
            real_fsync(path)

        request = self.adapter._attempt_request(
            1,
            bundle_digest=receipt["bundle"]["sha256"],
        )
        with mock.patch.object(
            DOCKER_BACKUP,
            "_fsync_bundle",
            side_effect=replace_with_fifo,
        ):
            with self.assertRaisesRegex(
                DOCKER_BACKUP.DockerBackupError,
                "^REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED$",
            ):
                self.adapter("fsync_backup", request)

    def test_symlink_swap_at_fsync_boundary_is_rejected(self) -> None:
        receipt = self._run_backup()
        bundle = self.transaction / "backup-attempt-01" / "bundle"
        database = bundle / "state/database.sqlite3"
        real_fsync = DOCKER_BACKUP._fsync_bundle

        def replace_with_symlink(path: Path) -> None:
            database.unlink()
            database.symlink_to(self.config)
            real_fsync(path)

        request = self.adapter._attempt_request(
            1,
            bundle_digest=receipt["bundle"]["sha256"],
        )
        with mock.patch.object(
            DOCKER_BACKUP,
            "_fsync_bundle",
            side_effect=replace_with_symlink,
        ):
            with self.assertRaisesRegex(
                DOCKER_BACKUP.DockerBackupError,
                "^REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED$",
            ):
                self.adapter("fsync_backup", request)

    def test_exact_orphan_archive_container_is_reaped_before_backend_start(self) -> None:
        attempt = self.transaction / "backup-attempt-01"
        attempt.mkdir(mode=0o700)
        bundle = attempt / "bundle"
        bundle.mkdir(mode=0o700)
        self.fake.backend_document[0]["State"] = {
            "Running": False,
            "Status": "exited",
        }
        identifier = self.fake.add_orphan(
            self.adapter,
            number=1,
            role="archive",
        )
        self.fake.calls.clear()

        result = self.adapter(
            "start_backend",
            {"container_id": self.container_id},
        )

        self.assertEqual(result["status"], "started")
        self.assertNotIn(identifier, self.fake.auxiliaries)
        mutations = [
            argv
            for argv, _timeout in self.fake.calls
            if "container" in argv
            and any(action in argv for action in ("stop", "rm", "start"))
        ]
        self.assertIn(identifier, mutations[0])
        self.assertIn("--timeout", mutations[0])
        self.assertNotIn("--time", mutations[0])
        self.assertEqual(mutations[1][-1], self.container_id)

    def test_normalize_uses_only_the_minimal_traversal_capability(self) -> None:
        receipt = self._run_backup()
        self.assertEqual(receipt["status"], "backup_ready")
        auxiliary_runs = [
            argv for argv, _timeout in self.fake.calls if "run" in argv
        ]
        by_role = {
            role: next(
                argv
                for argv in auxiliary_runs
                if argv[argv.index("--name") + 1].endswith("-" + role)
            )
            for role in ("normalize", "prepare")
        }

        def capabilities(argv: list[str]) -> list[str]:
            return [
                argv[index + 1]
                for index, value in enumerate(argv)
                if value == "--cap-add"
            ]

        self.assertEqual(
            capabilities(by_role["normalize"]),
            ["CHOWN", "DAC_READ_SEARCH", "FOWNER"],
        )
        self.assertEqual(
            capabilities(by_role["prepare"]),
            ["CHOWN", "FOWNER"],
        )
        self.assertNotIn("DAC_OVERRIDE", by_role["normalize"])

    def test_exact_canonical_normalize_orphan_is_reaped(self) -> None:
        attempt = self.transaction / "backup-attempt-01"
        attempt.mkdir(mode=0o700)
        (attempt / "bundle").mkdir(mode=0o700)
        self.fake.backend_document[0]["State"] = {
            "Running": False,
            "Status": "exited",
        }
        identifier = self.fake.add_orphan(
            self.adapter,
            number=1,
            role="normalize",
        )
        self.fake.calls.clear()

        result = self.adapter(
            "start_backend",
            {"container_id": self.container_id},
        )

        self.assertEqual(result["status"], "started")
        self.assertNotIn(identifier, self.fake.auxiliaries)

    def test_noncanonical_normalize_capabilities_fail_closed(self) -> None:
        invalid_capabilities = {
            "missing": ["CAP_CHOWN", "CAP_FOWNER"],
            "substituted": [
                "CAP_CHOWN",
                "CAP_DAC_OVERRIDE",
                "CAP_FOWNER",
            ],
            "extra": [
                "CAP_CHOWN",
                "CAP_DAC_READ_SEARCH",
                "CAP_FOWNER",
                "CAP_SYS_ADMIN",
            ],
        }
        for name, capabilities in invalid_capabilities.items():
            with self.subTest(name=name):
                self.fake.auxiliaries.clear()
                attempt = self.transaction / "backup-attempt-01"
                attempt.mkdir(mode=0o700, exist_ok=True)
                (attempt / "bundle").mkdir(mode=0o700, exist_ok=True)
                identifier = self.fake.add_orphan(
                    self.adapter,
                    number=1,
                    role="normalize",
                )
                self.fake.auxiliaries[identifier][0]["HostConfig"][
                    "CapAdd"
                ] = capabilities
                self.fake.calls.clear()

                with self.assertRaisesRegex(
                    DOCKER_BACKUP.DockerBackupError,
                    "^REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED$",
                ):
                    self.adapter(
                        "start_backend",
                        {"container_id": self.container_id},
                    )

                self.assertIn(identifier, self.fake.auxiliaries)
                self.assertFalse(
                    any(
                        "container" in argv
                        and any(item in argv for item in ("stop", "rm", "start"))
                        for argv, _timeout in self.fake.calls
                    )
                )

    def test_unknown_matching_orphan_fails_closed_without_removal(self) -> None:
        attempt = self.transaction / "backup-attempt-01"
        attempt.mkdir(mode=0o700)
        (attempt / "bundle").mkdir(mode=0o700)
        identifier = self.fake.add_orphan(
            self.adapter,
            number=1,
            role="archive",
        )
        self.fake.auxiliaries[identifier][0]["Config"]["User"] = "0:0"
        self.fake.calls.clear()

        with self.assertRaisesRegex(
            DOCKER_BACKUP.DockerBackupError,
            "^REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED$",
        ):
            self.adapter(
                "start_backend",
                {"container_id": self.container_id},
            )

        self.assertIn(identifier, self.fake.auxiliaries)
        self.assertFalse(
            any("rm" in argv for argv, _timeout in self.fake.calls)
        )


if __name__ == "__main__":
    unittest.main()
