# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "services/backend/scripts/reconcile_compose_deployment.py"


def _load_script():
    specification = importlib.util.spec_from_file_location(
        "tacua_compose_reconciler_test", SCRIPT
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("reconciler cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


RECONCILER = _load_script()
SYNTHETIC_DAEMON = {
    "cgroup_driver": "systemd",
    "cgroup_version": "2",
    "docker_root_directory": "/private/docker",
    "id": "synthetic-rootless-daemon",
    "security_options": [
        "name=rootless",
        "name=seccomp,profile=builtin",
    ],
}
SYNTHETIC_RUNTIME = {
    "docker_host": "unix:///run/user/501/docker.sock",
    "home": "/private/home",
    "xdg_runtime_directory": "/run/user/501",
}


class ComposeReconcilerTests(unittest.TestCase):
    def _fixture(self, root: Path, *, desired_state: str = "maintenance") -> Path:
        root = root.resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.chmod(0o700)
        state = root / "state"
        state.mkdir(mode=0o700)
        operation = root / "operations"
        operation.mkdir(mode=0o700)
        config = root / "config.json"
        config.write_text("{}", encoding="ascii")
        config.chmod(0o644)
        secret = root / "admin-secret"
        secret.write_text("synthetic-test-secret\n", encoding="ascii")
        secret.chmod(0o444)
        compose_document = {
            "name": "reconcile-test",
            "networks": {
                "private": {"name": "reconcile-test_private"},
                "publish": {"name": "reconcile-test_publish"},
            },
            "services": {},
            "volumes": {
                "tacua-state": {"name": "reconcile-test_tacua-state"}
            },
        }
        compose_payload = RECONCILER._canonical(compose_document)
        generation = state / "generations" / "generation-1"
        generation.mkdir(mode=0o700, parents=True)
        (state / "generations").chmod(0o700)
        compose = generation / RECONCILER.COMPOSE_FILE
        compose.write_bytes(compose_payload)
        compose.chmod(0o400)
        manifest = {
            "commands": {
                "docker": "/usr/bin/docker",
                "docker_service": "docker.service",
                "systemctl": "/usr/bin/systemctl",
                "tailscale": "/usr/bin/tailscale",
            },
            "compose_digest": RECONCILER._digest(compose_payload),
            "config": RECONCILER._identity(config, secret=False),
            "containers": {service: {} for service in RECONCILER.SERVICES},
            "contract_version": RECONCILER.GENERATION_CONTRACT,
            "daemon": SYNTHETIC_DAEMON,
            "generation": "generation-1",
            "manifest_digest": "",
            "operation_directory": str(operation),
            "project": "reconcile-test",
            "published_port": 8080,
            "resources": {"networks": {}, "volumes": {}},
            "runtime": SYNTHETIC_RUNTIME,
            "secret": RECONCILER._identity(secret, secret=True),
        }
        manifest["manifest_digest"] = RECONCILER._document_digest(
            manifest, "manifest_digest"
        )
        manifest_path = generation / RECONCILER.MANIFEST_FILE
        manifest_path.write_bytes(RECONCILER._canonical(manifest))
        manifest_path.chmod(0o600)
        desired = {
            "compose_digest": manifest["compose_digest"],
            "contract_version": RECONCILER.DESIRED_CONTRACT,
            "desired": desired_state,
            "generation": "generation-1",
            "manifest_digest": manifest["manifest_digest"],
            "project": "reconcile-test",
            "state_digest": "",
        }
        desired["state_digest"] = RECONCILER._document_digest(
            desired, "state_digest"
        )
        desired_path = state / RECONCILER.DESIRED_FILE
        desired_path.write_bytes(RECONCILER._canonical(desired))
        desired_path.chmod(0o600)
        return state

    def test_maintenance_reconcile_has_no_subprocess_or_lock_side_effect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self._fixture(Path(directory))
            runner = mock.Mock(side_effect=AssertionError("runner was called"))
            result = RECONCILER.reconcile(state, runner=runner)
            self.assertEqual(
                {"code": "RECONCILE_MAINTENANCE", "status": "maintenance"},
                result,
            )
            runner.assert_not_called()

    def test_desired_state_rejects_tamper_duplicate_keys_and_unsafe_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self._fixture(Path(directory))
            desired = state / RECONCILER.DESIRED_FILE
            payload = json.loads(desired.read_text(encoding="ascii"))
            payload["desired"] = "running"
            desired.write_bytes(RECONCILER._canonical(payload))
            with self.assertRaisesRegex(RECONCILER.ReconcileError, "RECONCILE_STATE_INVALID"):
                RECONCILER.reconcile(state)

            state = self._fixture(Path(directory) / "second")
            desired = state / RECONCILER.DESIRED_FILE
            desired.write_text('{"a":1,"a":2}', encoding="ascii")
            with self.assertRaisesRegex(RECONCILER.ReconcileError, "RECONCILE_STATE_INVALID"):
                RECONCILER.reconcile(state)

            state = self._fixture(Path(directory) / "third")
            desired = state / RECONCILER.DESIRED_FILE
            desired.chmod(0o640)
            with self.assertRaisesRegex(RECONCILER.ReconcileError, "RECONCILE_STATE_INVALID"):
                RECONCILER.reconcile(state)

    def test_live_restart_policy_accepts_only_unless_stopped_zero(self) -> None:
        self.assertTrue(
            RECONCILER._restart_policy_valid({"Name": "unless-stopped"})
        )
        self.assertTrue(
            RECONCILER._restart_policy_valid(
                {"Name": "unless-stopped", "MaximumRetryCount": 0}
            )
        )
        for value in (
            {"Name": "always", "MaximumRetryCount": 0},
            {"Name": "unless-stopped", "MaximumRetryCount": 1},
            {"Name": "unless-stopped", "MaximumRetryCount": False},
            None,
        ):
            self.assertFalse(RECONCILER._restart_policy_valid(value))

    def test_running_reconcile_contends_with_the_real_bridge_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self._fixture(Path(directory), desired_state="running")
            desired, _manifest, _compose = RECONCILER._load_bound_state(state)
            descriptor = RECONCILER._host_lock(desired["project"])
            try:
                with self.assertRaisesRegex(
                    RECONCILER.ReconcileError, "RECONCILE_DEFERRED"
                ):
                    RECONCILER.reconcile(state, runner=mock.Mock())
            finally:
                RECONCILER._release_lock(descriptor)
                Path(
                    f"/tmp/tacua-compose-processing-{desired['project']}.lock"
                ).unlink(missing_ok=True)

    def test_durable_processing_operation_inhibits_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self._fixture(Path(directory), desired_state="running")
            _desired, manifest, _compose = RECONCILER._load_bound_state(state)
            operation = Path(manifest["operation_directory"]) / (
                "tacua-compose-processing-" + manifest["project"]
            )
            operation.mkdir(mode=0o700)
            with self.assertRaisesRegex(
                RECONCILER.ReconcileError, "RECONCILE_RECOVERY_REQUIRED"
            ):
                RECONCILER._refuse_recovery_journal(manifest)

    def test_daemon_loss_disables_serve_before_start_and_enables_after_gates(self) -> None:
        manifest = {
            "commands": {
                "docker": "/usr/bin/docker",
                "docker_service": "docker.service",
                "systemctl": "/usr/bin/systemctl",
                "tailscale": "/usr/bin/tailscale",
            },
            "daemon": SYNTHETIC_DAEMON,
            "runtime": SYNTHETIC_RUNTIME,
        }
        events: list[str] = []
        deployment = {"containers": {}, "resources": {}}
        with mock.patch.object(RECONCILER, "_refuse_recovery_journal"), mock.patch.object(
            RECONCILER, "_tailnet_state", side_effect=[({}, True), ({}, True), ({}, True)]
        ), mock.patch.object(
            RECONCILER, "_docker_active", return_value=False
        ), mock.patch.object(
            RECONCILER, "_disable_serve", side_effect=lambda *_args: events.append("disable")
        ), mock.patch.object(
            RECONCILER, "_start_docker", side_effect=lambda *_args: events.append("docker")
        ), mock.patch.object(
            RECONCILER,
            "_daemon_projection",
            return_value=SYNTHETIC_DAEMON,
        ), mock.patch.object(
            RECONCILER, "_inspect_deployment", return_value=(deployment, True)
        ), mock.patch.object(
            RECONCILER, "_smoke", side_effect=lambda _manifest, public: events.append("public-smoke" if public else "loopback-smoke")
        ), mock.patch.object(
            RECONCILER, "_enable_serve", side_effect=lambda *_args: events.append("enable")
        ):
            result = RECONCILER._recover_locked(manifest, Path("/sealed/compose"), mock.Mock())
        self.assertEqual("recovered", result)
        self.assertEqual(
            ["disable", "docker", "loopback-smoke", "enable", "public-smoke"],
            events,
        )

    def test_post_start_failure_leaves_serve_proven_empty(self) -> None:
        manifest = {
            "commands": {
                "docker": "/usr/bin/docker",
                "docker_service": "docker.service",
                "systemctl": "/usr/bin/systemctl",
                "tailscale": "/usr/bin/tailscale",
            },
            "daemon": SYNTHETIC_DAEMON,
            "runtime": SYNTHETIC_RUNTIME,
        }
        disabled: list[bool] = []
        with mock.patch.object(RECONCILER, "_refuse_recovery_journal"), mock.patch.object(
            RECONCILER, "_tailnet_state", return_value=({}, True)
        ), mock.patch.object(
            RECONCILER, "_docker_active", return_value=False
        ), mock.patch.object(RECONCILER, "_start_docker"), mock.patch.object(
            RECONCILER,
            "_daemon_projection",
            return_value=SYNTHETIC_DAEMON,
        ), mock.patch.object(
            RECONCILER,
            "_disable_serve",
            side_effect=lambda *_args: disabled.append(True),
        ), mock.patch.object(
            RECONCILER,
            "_inspect_deployment",
            side_effect=RECONCILER.ReconcileError("RECONCILE_CONTAINER_DRIFT"),
        ):
            with self.assertRaisesRegex(
                RECONCILER.ReconcileError, "RECONCILE_CONTAINER_DRIFT"
            ):
                RECONCILER._recover_locked(manifest, Path("/sealed/compose"), mock.Mock())
        self.assertEqual([True], disabled)

    def test_critical_code_wins_when_serve_cannot_be_proven_empty(self) -> None:
        manifest = {
            "commands": {
                "docker": "/usr/bin/docker",
                "docker_service": "docker.service",
                "systemctl": "/usr/bin/systemctl",
                "tailscale": "/usr/bin/tailscale",
            },
            "daemon": SYNTHETIC_DAEMON,
            "runtime": SYNTHETIC_RUNTIME,
        }
        with mock.patch.object(RECONCILER, "_refuse_recovery_journal"), mock.patch.object(
            RECONCILER, "_tailnet_state", return_value=({}, True)
        ), mock.patch.object(
            RECONCILER, "_docker_active", return_value=False
        ), mock.patch.object(
            RECONCILER,
            "_disable_serve",
            side_effect=RECONCILER.ReconcileError(
                "RECONCILE_PUBLIC_PATH_CRITICAL"
            ),
        ):
            with self.assertRaisesRegex(
                RECONCILER.ReconcileError,
                "RECONCILE_PUBLIC_PATH_CRITICAL",
            ):
                RECONCILER._recover_locked(
                    manifest, Path("/sealed/compose"), mock.Mock()
                )

    def test_enable_validation_failure_forces_disable_and_empty_proof(self) -> None:
        manifest = {
            "commands": {
                "docker": "/usr/bin/docker",
                "docker_service": "docker.service",
                "systemctl": "/usr/bin/systemctl",
                "tailscale": "/usr/bin/tailscale",
            },
            "daemon": SYNTHETIC_DAEMON,
            "runtime": SYNTHETIC_RUNTIME,
        }
        disabled: list[bool] = []
        with mock.patch.object(RECONCILER, "_refuse_recovery_journal"), mock.patch.object(
            RECONCILER, "_tailnet_state", return_value=({}, False)
        ), mock.patch.object(
            RECONCILER, "_docker_active", return_value=True
        ), mock.patch.object(
            RECONCILER,
            "_daemon_projection",
            return_value=SYNTHETIC_DAEMON,
        ), mock.patch.object(
            RECONCILER,
            "_inspect_deployment",
            return_value=({"containers": {}, "resources": {}}, True),
        ), mock.patch.object(RECONCILER, "_smoke"), mock.patch.object(
            RECONCILER,
            "_enable_serve",
            side_effect=RECONCILER.ReconcileError("RECONCILE_TAILNET_FAILED"),
        ), mock.patch.object(
            RECONCILER,
            "_disable_serve",
            side_effect=lambda *_args: disabled.append(True),
        ):
            with self.assertRaisesRegex(
                RECONCILER.ReconcileError, "RECONCILE_TAILNET_FAILED"
            ):
                RECONCILER._recover_locked(
                    manifest, Path("/sealed/compose"), mock.Mock()
                )
        self.assertEqual([True], disabled)

    def test_activation_crash_marker_makes_maintenance_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self._fixture(Path(directory), desired_state="maintenance")
            with mock.patch.object(
                RECONCILER,
                "_recover_locked",
                side_effect=SystemExit("synthetic crash after activation"),
            ):
                with self.assertRaises(SystemExit):
                    RECONCILER.set_running(state, runner=mock.Mock())
            desired, _manifest, _compose = RECONCILER._load_bound_state(state)
            self.assertEqual("maintenance", desired["desired"])
            self.assertIsNotNone(RECONCILER._load_activation(state, desired))

            with mock.patch.object(
                RECONCILER, "_recover_locked", return_value="healthy"
            ):
                result = RECONCILER.reconcile(state, runner=mock.Mock())
            self.assertEqual("healthy", result["status"])
            desired, _manifest, _compose = RECONCILER._load_bound_state(state)
            self.assertEqual("running", desired["desired"])
            self.assertIsNone(RECONCILER._load_activation(state, desired))

    def test_smoke_builds_only_explicit_no_proxy_openers(self) -> None:
        manifest = {
            "config": {"path": "/private/config"},
            "published_port": 8080,
            "secret": {"path": "/private/secret"},
        }
        built: list[tuple[object, ...]] = []

        def fake_build_opener(*handlers):
            built.append(handlers)
            return object()

        def fake_smoke(*_args, **kwargs):
            kwargs["opener_factory"](mock.Mock())
            return {"status": "ok"}

        with mock.patch.object(
            RECONCILER.urllib.request,
            "build_opener",
            side_effect=fake_build_opener,
        ), mock.patch.object(
            RECONCILER, "smoke_deployment", side_effect=fake_smoke
        ), mock.patch.object(RECONCILER, "_reviewer_smoke"):
            RECONCILER._smoke(manifest, public=False)
        self.assertEqual(1, len(built))
        proxy_handlers = [
            handler
            for handler in built[0]
            if isinstance(handler, RECONCILER.urllib.request.ProxyHandler)
        ]
        self.assertEqual(1, len(proxy_handlers))
        self.assertEqual({}, proxy_handlers[0].proxies)

    def test_rootless_daemon_projection_rejects_rootful_and_identity_drift(self) -> None:
        manifest = {
            "commands": {"docker": "/usr/bin/docker"},
            "runtime": SYNTHETIC_RUNTIME,
        }
        rootless = {
            "CgroupDriver": "systemd",
            "CgroupVersion": "2",
            "DockerRootDir": "/private/docker",
            "ID": "synthetic-rootless-daemon",
            "SecurityOptions": [
                "name=seccomp,profile=builtin",
                "name=rootless",
            ],
        }
        runner = mock.Mock(return_value=RECONCILER._canonical(rootless))
        self.assertEqual(
            SYNTHETIC_DAEMON,
            RECONCILER._daemon_projection(manifest, runner),
        )
        rootful = dict(rootless)
        rootful["SecurityOptions"] = ["name=seccomp,profile=builtin"]
        runner.return_value = RECONCILER._canonical(rootful)
        with self.assertRaisesRegex(
            RECONCILER.ReconcileError, "RECONCILE_RUNTIME_DRIFT"
        ):
            RECONCILER._daemon_projection(manifest, runner)
        changed = dict(rootless)
        changed["ID"] = "different-daemon"
        runner.return_value = RECONCILER._canonical(changed)
        self.assertNotEqual(
            SYNTHETIC_DAEMON,
            RECONCILER._daemon_projection(manifest, runner),
        )

    def test_network_projection_binds_exact_consumer_ids(self) -> None:
        first = "a" * 64
        second = "b" * 64
        base = {
            "Attachable": False,
            "Containers": {first: {}},
            "Driver": "bridge",
            "Id": "network-id",
            "Ingress": False,
            "Internal": True,
            "Labels": {"com.docker.compose.project": "reconcile-test"},
            "Name": "reconcile-test_private",
            "Options": {},
        }
        expected = RECONCILER._resource_projection([base], network=True)
        rogue = dict(base)
        rogue["Containers"] = {first: {}, second: {}}
        actual = RECONCILER._resource_projection([rogue], network=True)
        self.assertEqual([first], expected["ContainerIDs"])
        self.assertEqual([first, second], actual["ContainerIDs"])
        self.assertNotEqual(expected, actual)

    def test_container_projection_rejects_mutated_resource_limits(self) -> None:
        container_id = "a" * 64
        document = [{
            "Config": {
                "Healthcheck": {"Test": ["CMD", "true"]},
                "Image": "tacua-backend:test",
                "Labels": {
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "reconcile-test",
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
                    "Type": "json-file",
                    "Config": {"max-file": "3", "max-size": "10m"},
                },
                "NetworkMode": "reconcile-test_private",
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
            "Id": container_id,
            "Image": "sha256:" + "b" * 64,
            "Mounts": [],
            "Name": "/reconcile-test-backend-1",
            "NetworkSettings": {"Networks": {}},
        }]
        projection = RECONCILER._container_projection(
            document,
            project="reconcile-test",
            service="backend",
        )
        self.assertEqual(128, projection["host"]["PidsLimit"])
        document[0]["HostConfig"]["PidsLimit"] = 0
        with self.assertRaisesRegex(
            RECONCILER.ReconcileError, "RECONCILE_CONTAINER_DRIFT"
        ):
            RECONCILER._container_projection(
                document,
                project="reconcile-test",
                service="backend",
            )

    def test_generic_tailnet_gate_accepts_immutable_preflight_profile(self) -> None:
        status = {"synthetic": "status"}
        serve = {"synthetic": "serve"}
        runner = mock.Mock(
            side_effect=[
                RECONCILER._canonical(serve),
                RECONCILER._canonical(status),
            ]
        )
        manifest = {
            "commands": {"tailscale": "/usr/bin/tailscale"},
            "config": {"path": "/private/config"},
        }
        with mock.patch.object(
            RECONCILER,
            "load_public_config",
            return_value=SimpleNamespace(
                backend_origin="https://node.example-tail.ts.net"
            ),
        ), mock.patch.object(
            RECONCILER.tailnet_gate,
            "_validate_tailnet_status",
            return_value="node.example-tail.ts.net",
        ), mock.patch.object(
            RECONCILER.tailnet_gate, "_validate_serve_status"
        ) as serve_validator:
            _status, active = RECONCILER._tailnet_state(
                manifest,
                Path("/sealed/immutable-compose.json"),
                runner,
            )
        self.assertTrue(active)
        serve_validator.assert_called_once_with(
            serve, "node.example-tail.ts.net"
        )

    def test_systemd_unit_uses_exact_shared_lock_exception(self) -> None:
        service = (
            ROOT / "services/backend/systemd/tacua-reconcile.service.in"
        ).read_text(encoding="utf-8")
        lock_service = (
            ROOT
            / "services/backend/systemd/tacua-reconcile-lock.service.in"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'ReadWritePaths="@STATE_DIRECTORY@" "@LOCK_FILE@"',
            service,
        )
        self.assertNotIn("ReadWritePaths=/tmp\n", service)
        self.assertIn("Requires=tacua-reconcile-lock.service", service)
        self.assertIn(" prepare-lock --state-directory ", lock_service)

    def test_unit_name_cannot_be_parsed_as_a_systemctl_option(self) -> None:
        self.assertIsNone(RECONCILER.UNIT.fullmatch("-evil.service"))
        self.assertIsNotNone(RECONCILER.UNIT.fullmatch("docker.service"))

    def test_crash_after_running_publish_keeps_activation_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self._fixture(Path(directory), desired_state="maintenance")
            with mock.patch.object(
                RECONCILER, "_recover_locked", return_value="healthy"
            ), mock.patch.object(
                RECONCILER,
                "_remove_activation",
                side_effect=SystemExit("synthetic crash after state publish"),
            ):
                with self.assertRaises(SystemExit):
                    RECONCILER.set_running(state, runner=mock.Mock())
            desired, _manifest, _compose = RECONCILER._load_bound_state(state)
            self.assertEqual("running", desired["desired"])
            self.assertIsNotNone(RECONCILER._load_activation(state, desired))
            with mock.patch.object(
                RECONCILER, "_recover_locked", return_value="healthy"
            ):
                RECONCILER.reconcile(state, runner=mock.Mock())
            desired, _manifest, _compose = RECONCILER._load_bound_state(state)
            self.assertEqual("running", desired["desired"])
            self.assertIsNone(RECONCILER._load_activation(state, desired))

    def test_seal_accepts_real_preflight_config_and_read_only_secret_contract(self) -> None:
        from services.backend.tests.test_operator_tool import (
            OperatorToolTests as OperatorFixture,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.chmod(0o700)
            helper = OperatorFixture()
            config, secret, backend_state = helper.deployment(root)
            compose_document = helper.compose_document(
                immutable=True,
                state_target=str(backend_state),
                config_source=str(config),
                secret_source=str(secret),
            )
            compose = root / "resolved-compose.json"
            compose.write_bytes(RECONCILER._canonical(compose_document))
            compose.chmod(0o600)
            operation = root / "operations"
            operation.mkdir(mode=0o700)
            state_directory = root / "reconciler"
            args = SimpleNamespace(
                admin_secret_file=secret,
                allow_mutable_image=False,
                compose_json=compose,
                config_file=config,
                docker_service="docker.service",
                generation="generation-real-preflight",
                operation_directory=operation,
                project="test",
                state_directory=state_directory,
            )
            deployment = {
                "containers": {
                    service: {} for service in RECONCILER.SERVICES
                },
                "resources": {"networks": {}, "volumes": {}},
            }
            with mock.patch.object(
                RECONCILER, "_runtime_binding", return_value=SYNTHETIC_RUNTIME
            ), mock.patch.object(
                RECONCILER,
                "_binary",
                side_effect=lambda name: f"/usr/bin/{name}",
            ), mock.patch.object(
                RECONCILER, "_host_lock", return_value=99
            ), mock.patch.object(
                RECONCILER, "_release_lock"
            ), mock.patch.object(
                RECONCILER, "_refuse_recovery_journal"
            ), mock.patch.object(
                RECONCILER,
                "_daemon_projection",
                return_value=SYNTHETIC_DAEMON,
            ), mock.patch.object(
                RECONCILER,
                "_inspect_deployment",
                return_value=(deployment, True),
            ), mock.patch.object(
                RECONCILER, "_smoke"
            ), mock.patch.object(
                RECONCILER, "_tailnet_state", return_value=({}, True)
            ):
                result = RECONCILER.seal(args, runner=mock.Mock())
            self.assertEqual("healthy", result["status"])
            desired, manifest, _compose = RECONCILER._load_bound_state(
                state_directory
            )
            self.assertEqual("running", desired["desired"])
            self.assertEqual(0o444, manifest["secret"]["mode"])
            self.assertEqual(0o644, manifest["config"]["mode"])

    def test_cancel_crash_after_disable_is_resumed_as_cancel_not_activation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self._fixture(Path(directory), desired_state="maintenance")
            desired, _manifest, _compose = RECONCILER._load_bound_state(state)
            RECONCILER._write_activation(state, desired)
            disabled: list[bool] = []
            with mock.patch.object(
                RECONCILER, "_tailnet_state", return_value=({}, True)
            ), mock.patch.object(
                RECONCILER,
                "_disable_serve",
                side_effect=lambda *_args: disabled.append(True),
            ), mock.patch.object(
                RECONCILER,
                "_remove_activation",
                side_effect=SystemExit("synthetic crash after disable"),
            ):
                with self.assertRaises(SystemExit):
                    RECONCILER.cancel_activation(state, runner=mock.Mock())
            desired, _manifest, _compose = RECONCILER._load_bound_state(state)
            activation = RECONCILER._load_activation(state, desired)
            self.assertEqual([True], disabled)
            self.assertIsNotNone(activation)
            self.assertEqual("canceling", activation["intent"])
            self.assertEqual(
                "canceling",
                RECONCILER._reported_status(desired, activation),
            )

            with mock.patch.object(
                RECONCILER, "_tailnet_state", return_value=({}, False)
            ), mock.patch.object(
                RECONCILER, "_recover_locked"
            ) as recover:
                result = RECONCILER.reconcile(state, runner=mock.Mock())
            self.assertEqual("maintenance", result["status"])
            recover.assert_not_called()
            self.assertIsNone(RECONCILER._load_activation(state, desired))

    def test_maintenance_transition_crash_never_recovers_running(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self._fixture(Path(directory), desired_state="running")
            disabled: list[bool] = []
            with mock.patch.object(
                RECONCILER, "_tailnet_state", return_value=({}, True)
            ), mock.patch.object(
                RECONCILER,
                "_disable_serve",
                side_effect=lambda *_args: disabled.append(True),
            ), mock.patch.object(
                RECONCILER,
                "_remove_activation",
                side_effect=SystemExit("synthetic crash after maintenance"),
            ):
                with self.assertRaises(SystemExit):
                    RECONCILER.set_maintenance(state, runner=mock.Mock())
            desired, _manifest, _compose = RECONCILER._load_bound_state(state)
            transition = RECONCILER._load_activation(state, desired)
            self.assertEqual("maintenance", desired["desired"])
            self.assertEqual("maintenance", transition["intent"])
            self.assertEqual([True], disabled)
            with self.assertRaisesRegex(
                RECONCILER.ReconcileError,
                "RECONCILE_ACTIVATION_PENDING",
            ):
                RECONCILER.cancel_activation(state, runner=mock.Mock())
            self.assertEqual(
                "maintenance",
                RECONCILER._load_activation(state, desired)["intent"],
            )

            with mock.patch.object(
                RECONCILER, "_tailnet_state", return_value=({}, False)
            ), mock.patch.object(
                RECONCILER, "_recover_locked"
            ) as recover:
                result = RECONCILER.reconcile(state, runner=mock.Mock())
            self.assertEqual("maintenance", result["status"])
            recover.assert_not_called()
            self.assertIsNone(RECONCILER._load_activation(state, desired))

    def test_explicit_maintenance_rechecks_and_disables_active_serve(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self._fixture(Path(directory), desired_state="maintenance")
            disabled: list[bool] = []
            with mock.patch.object(
                RECONCILER, "_tailnet_state", return_value=({}, True)
            ), mock.patch.object(
                RECONCILER,
                "_disable_serve",
                side_effect=lambda *_args: disabled.append(True),
            ):
                result = RECONCILER.set_maintenance(
                    state,
                    runner=mock.Mock(),
                )
            self.assertEqual("maintenance", result["status"])
            self.assertEqual([True], disabled)

    def test_existing_maintenance_crash_marker_remains_timer_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self._fixture(Path(directory), desired_state="maintenance")
            with mock.patch.object(
                RECONCILER,
                "_write_desired",
                side_effect=SystemExit("synthetic crash after marker"),
            ):
                with self.assertRaises(SystemExit):
                    RECONCILER.set_maintenance(state, runner=mock.Mock())
            desired, _manifest, _compose = RECONCILER._load_bound_state(state)
            transition = RECONCILER._load_activation(state, desired)
            self.assertEqual("maintenance", transition["intent"])
            with mock.patch.object(
                RECONCILER, "_tailnet_state", return_value=({}, False)
            ):
                result = RECONCILER.reconcile(state, runner=mock.Mock())
            self.assertEqual("maintenance", result["status"])
            self.assertIsNone(RECONCILER._load_activation(state, desired))


if __name__ == "__main__":
    unittest.main()
