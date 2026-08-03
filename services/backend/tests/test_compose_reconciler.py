# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import os
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

    def _anchor_fixture(self, home: Path) -> tuple[Path, Path, Path]:
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
        home.chmod(0o700)
        state = self._fixture(home)
        runtime = home / "runtime"
        runtime.mkdir(mode=0o700)
        generation = state / "generations" / "generation-1"
        manifest_path = generation / RECONCILER.MANIFEST_FILE
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        manifest["runtime"] = {
            "docker_host": f"unix://{runtime}/docker.sock",
            "home": str(home),
            "xdg_runtime_directory": str(runtime),
        }
        manifest["manifest_digest"] = RECONCILER._document_digest(
            manifest, "manifest_digest"
        )
        manifest_path.write_bytes(RECONCILER._canonical(manifest))
        desired_path = state / RECONCILER.DESIRED_FILE
        desired = json.loads(desired_path.read_text(encoding="ascii"))
        desired["manifest_digest"] = manifest["manifest_digest"]
        desired["state_digest"] = RECONCILER._document_digest(
            desired, "state_digest"
        )
        desired_path.write_bytes(RECONCILER._canonical(desired))
        anchor = runtime / "tacua-reconcile.anchor.json"
        return state, runtime, anchor

    @contextlib.contextmanager
    def _anchor_environment(self, home: Path, runtime: Path):
        with mock.patch.object(
            RECONCILER, "_passwd_home", return_value=home
        ), mock.patch.object(
            RECONCILER,
            "_boot_id",
            return_value="12345678-1234-1234-1234-123456789abc",
        ), mock.patch.object(
            RECONCILER, "_overflow_uid", return_value=60001
        ), mock.patch.dict(
            os.environ, {"XDG_RUNTIME_DIR": str(runtime)}
        ):
            yield

    def _rewrite_anchor(self, anchor_path: Path, **changes) -> dict:
        anchor = json.loads(anchor_path.read_text(encoding="ascii"))
        anchor.update(changes)
        anchor["anchor_digest"] = RECONCILER._document_digest(
            anchor, "anchor_digest"
        )
        anchor_path.write_bytes(RECONCILER._canonical(anchor))
        anchor_path.chmod(0o600)
        return anchor

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

    def test_serve_enable_is_recovered_and_unchanged_serve_is_healthy(self) -> None:
        cases = (
            (
                False,
                {"code": "RECONCILE_RECOVERED", "status": "recovered"},
            ),
            (True, {"code": "RECONCILE_HEALTHY", "status": "healthy"}),
        )
        for active, expected in cases:
            with self.subTest(
                active=active
            ), tempfile.TemporaryDirectory() as directory:
                state = self._fixture(Path(directory), desired_state="running")
                deployment = {"containers": {}, "resources": {}}
                with mock.patch.object(
                    RECONCILER, "_host_lock", return_value=99
                ), mock.patch.object(
                    RECONCILER, "_release_lock"
                ), mock.patch.object(
                    RECONCILER, "_refuse_recovery_journal"
                ), mock.patch.object(
                    RECONCILER,
                    "_tailnet_state",
                    side_effect=[({}, active), ({}, True)],
                ), mock.patch.object(
                    RECONCILER, "_docker_active", return_value=True
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
                    RECONCILER, "_enable_serve"
                ) as enable:
                    result = RECONCILER.reconcile(state, runner=mock.Mock())
                self.assertEqual(expected, result)
                self.assertEqual(0 if active else 1, enable.call_count)

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
            self.assertEqual(
                {"code": "RECONCILE_RECOVERED", "status": "recovered"},
                result,
            )
            desired, _manifest, _compose = RECONCILER._load_bound_state(state)
            self.assertEqual("running", desired["desired"])
            self.assertIsNone(RECONCILER._load_activation(state, desired))

    def test_anchored_activation_completion_reports_recovered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            state, runtime, anchor_path = self._anchor_fixture(home)
            lock_path = RECONCILER._lock_path("reconcile-test")
            lock_path.unlink(missing_ok=True)
            try:
                with self._anchor_environment(home, runtime):
                    RECONCILER.prepare_lock(state, anchor_path)
                    desired, _manifest, _compose = RECONCILER._load_bound_state(
                        state
                    )
                    RECONCILER._write_activation(state, desired)
                    with mock.patch.object(
                        RECONCILER, "_recover_locked", return_value="healthy"
                    ):
                        result = RECONCILER.reconcile(
                            state,
                            runner=mock.Mock(),
                            anchor_file=anchor_path,
                        )
                self.assertEqual(
                    {"code": "RECONCILE_RECOVERED", "status": "recovered"},
                    result,
                )
                desired, _manifest, _compose = RECONCILER._load_bound_state(
                    state
                )
                self.assertEqual("running", desired["desired"])
                self.assertIsNone(RECONCILER._load_activation(state, desired))
            finally:
                lock_path.unlink(missing_ok=True)

    def test_set_running_state_publication_reports_recovered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = self._fixture(Path(directory), desired_state="maintenance")
            with mock.patch.object(
                RECONCILER, "_recover_locked", return_value="healthy"
            ):
                result = RECONCILER.set_running(state, runner=mock.Mock())
            self.assertEqual(
                {"code": "RECONCILE_RECOVERED", "status": "recovered"},
                result,
            )

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

    def test_recovery_accepts_only_unhealthy_sealed_network_consumer_subsets(
        self,
    ) -> None:
        first = "a" * 64
        second = "b" * 64
        unexpected = "c" * 64
        expected = {
            "networks": {
                "reconcile-test_private": {
                    "Attachable": False,
                    "ContainerIDs": [first, second],
                    "Driver": "bridge",
                    "Id": "private-network-id",
                    "Ingress": False,
                    "Internal": True,
                    "Labels": {
                        "com.docker.compose.project": "reconcile-test"
                    },
                    "Name": "reconcile-test_private",
                    "Options": {},
                }
            },
            "volumes": {
                "reconcile-test_tacua-state": {
                    "Driver": "local",
                    "Labels": {
                        "com.docker.compose.project": "reconcile-test"
                    },
                    "Name": "reconcile-test_tacua-state",
                    "Options": {},
                    "Scope": "local",
                }
            },
        }
        missing = json.loads(json.dumps(expected))
        missing["networks"]["reconcile-test_private"]["ContainerIDs"] = [
            first
        ]
        self.assertTrue(
            RECONCILER._validate_resources_against_sealed(
                missing,
                expected,
                allow_missing_network_consumers=True,
                all_healthy=False,
            )
        )
        for actual, allow, healthy in (
            (missing, False, False),
            (missing, True, True),
        ):
            with self.subTest(allow=allow, healthy=healthy), self.assertRaisesRegex(
                RECONCILER.ReconcileError,
                "RECONCILE_RESOURCE_DRIFT",
            ):
                RECONCILER._validate_resources_against_sealed(
                    actual,
                    expected,
                    allow_missing_network_consumers=allow,
                    all_healthy=healthy,
                )

        rogue = json.loads(json.dumps(missing))
        rogue["networks"]["reconcile-test_private"]["ContainerIDs"].append(
            unexpected
        )
        network_drift = json.loads(json.dumps(missing))
        network_drift["networks"]["reconcile-test_private"]["Internal"] = False
        volume_drift = json.loads(json.dumps(missing))
        volume_drift["volumes"]["reconcile-test_tacua-state"]["Options"] = {
            "unexpected": "value"
        }
        for label, actual in (
            ("unexpected consumer", rogue),
            ("network field", network_drift),
            ("volume field", volume_drift),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                RECONCILER.ReconcileError,
                "RECONCILE_RESOURCE_DRIFT",
            ):
                RECONCILER._validate_resources_against_sealed(
                    actual,
                    expected,
                    allow_missing_network_consumers=True,
                    all_healthy=False,
                )

    def test_network_reattachment_recovery_reinspects_strictly_after_start(
        self,
    ) -> None:
        manifest = {
            "commands": {
                "docker": "/usr/bin/docker",
                "docker_service": "docker.service",
                "systemctl": "/usr/bin/systemctl",
                "tailscale": "/usr/bin/tailscale",
            },
            "daemon": SYNTHETIC_DAEMON,
            "project": "reconcile-test",
            "runtime": SYNTHETIC_RUNTIME,
        }
        inspected_modes: list[bool] = []
        deployments = iter(
            [
                (
                    {
                        "containers": {"sealed": True},
                        "resources": {"subset": True},
                    },
                    False,
                ),
                (
                    {
                        "containers": {"sealed": True},
                        "resources": {"exact": True},
                    },
                    True,
                ),
            ]
        )

        def inspect(*_args, **kwargs):
            inspected_modes.append(
                kwargs.get("allow_missing_network_consumers", False)
            )
            return next(deployments)

        runner = mock.Mock(return_value=b"")
        with mock.patch.object(
            RECONCILER, "_refuse_recovery_journal"
        ), mock.patch.object(
            RECONCILER,
            "_tailnet_state",
            side_effect=[({}, False), ({}, True)],
        ), mock.patch.object(
            RECONCILER, "_docker_active", return_value=True
        ), mock.patch.object(
            RECONCILER,
            "_daemon_projection",
            return_value=SYNTHETIC_DAEMON,
        ), mock.patch.object(
            RECONCILER, "_inspect_deployment", side_effect=inspect
        ), mock.patch.object(
            RECONCILER, "_smoke"
        ), mock.patch.object(
            RECONCILER, "_enable_serve"
        ):
            result = RECONCILER._recover_locked(
                manifest,
                Path("/sealed/compose"),
                runner,
            )
        self.assertEqual("recovered", result)
        self.assertEqual([True, False], inspected_modes)
        runner.assert_called_once_with(
            [
                "/usr/bin/docker",
                "--host",
                SYNTHETIC_RUNTIME["docker_host"],
                "compose",
                "-p",
                "reconcile-test",
                "-f",
                "/sealed/compose",
                "start",
                *RECONCILER.SERVICES,
            ],
            timeout=60,
        )

    def test_exact_container_listings_request_untruncated_ids(self) -> None:
        calls: list[list[str]] = []

        def runner(argv, *, timeout):
            calls.append(argv)
            width = 64 if "--no-trunc" in argv else 12
            return (("a" * width) + "\n").encode("ascii")

        docker = ["/usr/bin/docker", "--host", "unix:///private/docker.sock"]
        for filter_value, code in (
            (
                "label=com.docker.compose.project=reconcile-test",
                "RECONCILE_CONTAINER_DRIFT",
            ),
            ("volume=reconcile-test_state", "RECONCILE_RESOURCE_DRIFT"),
        ):
            self.assertEqual(
                {"a" * 64},
                RECONCILER._listed_container_ids(
                    runner,
                    docker,
                    filter_value,
                    code,
                ),
            )
        self.assertEqual(2, len(calls))
        self.assertTrue(all("--no-trunc" in call for call in calls))
        self.assertEqual(
            {
                "label=com.docker.compose.project=reconcile-test",
                "volume=reconcile-test_state",
            },
            {call[-1] for call in calls},
        )

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

    def test_prepare_lock_publishes_bound_anchor_and_preserves_lock_inode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            state, runtime, anchor_path = self._anchor_fixture(home)
            lock_path = RECONCILER._lock_path("reconcile-test")
            lock_path.unlink(missing_ok=True)
            try:
                with self._anchor_environment(home, runtime):
                    RECONCILER.prepare_lock(state, anchor_path)
                    first_inode = lock_path.stat().st_ino
                    anchor = RECONCILER._load_anchor(anchor_path, state)
                    self.assertEqual(first_inode, anchor["lock"]["inode"])
                    self.assertEqual(60001, anchor["overflow_uid"])
                    result = RECONCILER.reconcile(
                        state,
                        runner=mock.Mock(),
                        anchor_file=anchor_path,
                    )
                    self.assertEqual("maintenance", result["status"])
                    RECONCILER.prepare_lock(state, anchor_path)
                    self.assertEqual(first_inode, lock_path.stat().st_ino)
            finally:
                lock_path.unlink(missing_ok=True)

    def test_prepare_failure_leaves_only_nontrusted_pending_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            state, runtime, anchor_path = self._anchor_fixture(home)
            lock_path = RECONCILER._lock_path("reconcile-test")
            lock_path.unlink(missing_ok=True)
            try:
                with self._anchor_environment(home, runtime):
                    RECONCILER.prepare_lock(state, anchor_path)
                    with mock.patch.object(
                        RECONCILER,
                        "_open_host_lock",
                        side_effect=RECONCILER.ReconcileError(
                            "RECONCILE_LOCK_INVALID"
                        ),
                    ):
                        with self.assertRaisesRegex(
                            RECONCILER.ReconcileError,
                            "RECONCILE_LOCK_INVALID",
                        ):
                            RECONCILER.prepare_lock(state, anchor_path)
                    pending = json.loads(anchor_path.read_text(encoding="ascii"))
                    self.assertEqual(
                        RECONCILER.ANCHOR_PENDING_CONTRACT,
                        pending["contract_version"],
                    )
                    with self.assertRaisesRegex(
                        RECONCILER.ReconcileError,
                        "RECONCILE_ANCHOR_INVALID",
                    ):
                        RECONCILER._load_anchor(anchor_path, state)
            finally:
                lock_path.unlink(missing_ok=True)

    def test_anchor_rejects_noncanonical_mode_owner_link_and_symlink(self) -> None:
        cases = ("noncanonical", "mode", "owner", "hardlink", "symlink")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                home = Path(directory).resolve()
                state, runtime, anchor_path = self._anchor_fixture(home)
                lock_path = RECONCILER._lock_path("reconcile-test")
                lock_path.unlink(missing_ok=True)
                try:
                    with self._anchor_environment(home, runtime):
                        RECONCILER.prepare_lock(state, anchor_path)
                        owner_patch = contextlib.nullcontext()
                        if case == "noncanonical":
                            document = json.loads(
                                anchor_path.read_text(encoding="ascii")
                            )
                            anchor_path.write_text(
                                json.dumps(document, indent=2), encoding="ascii"
                            )
                        elif case == "mode":
                            anchor_path.chmod(0o640)
                        elif case == "owner":
                            owner_patch = mock.patch.object(
                                RECONCILER.os,
                                "geteuid",
                                return_value=os.geteuid() + 1,
                            )
                        elif case == "hardlink":
                            os.link(anchor_path, runtime / "second-link")
                        else:
                            target = runtime / "anchor-target"
                            anchor_path.replace(target)
                            anchor_path.symlink_to(target)
                        with owner_patch, self.assertRaisesRegex(
                            RECONCILER.ReconcileError,
                            "RECONCILE_ANCHOR_INVALID",
                        ):
                            RECONCILER._load_anchor(anchor_path, state)
                finally:
                    lock_path.unlink(missing_ok=True)

    def test_anchor_rejects_path_project_identity_and_boot_mismatches(self) -> None:
        mutations = (
            ("state-device", lambda value: value["state_directory"].__setitem__("device", value["state_directory"]["device"] + 1)),
            ("operation-inode", lambda value: value["operation_directory"].__setitem__("inode", value["operation_directory"]["inode"] + 1)),
            ("lock-inode", lambda value: value["lock"].__setitem__("inode", value["lock"]["inode"] + 1)),
            ("project", lambda value: value.__setitem__("project", "different-project")),
            ("boot", lambda value: value.__setitem__("boot_id", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
            ("overflow", lambda value: value.__setitem__("overflow_uid", 60002)),
            ("dot-path", lambda value: value["state_directory"].__setitem__("path", value["home"]["path"] + "/state/../state")),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                home = Path(directory).resolve()
                state, runtime, anchor_path = self._anchor_fixture(home)
                lock_path = RECONCILER._lock_path("reconcile-test")
                lock_path.unlink(missing_ok=True)
                try:
                    with self._anchor_environment(home, runtime):
                        RECONCILER.prepare_lock(state, anchor_path)
                        anchor = json.loads(anchor_path.read_text(encoding="ascii"))
                        mutate(anchor)
                        anchor["anchor_digest"] = RECONCILER._document_digest(
                            anchor, "anchor_digest"
                        )
                        anchor_path.write_bytes(RECONCILER._canonical(anchor))
                        with self.assertRaisesRegex(
                            RECONCILER.ReconcileError,
                            "RECONCILE_ANCHOR_INVALID",
                        ):
                            RECONCILER.reconcile(
                                state,
                                runner=mock.Mock(),
                                anchor_file=anchor_path,
                            )
                finally:
                    lock_path.unlink(missing_ok=True)

    def test_manifest_binding_mismatch_is_rejected_after_lock_before_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            state, runtime, anchor_path = self._anchor_fixture(home)
            lock_path = RECONCILER._lock_path("reconcile-test")
            lock_path.unlink(missing_ok=True)
            try:
                with self._anchor_environment(home, runtime):
                    RECONCILER.prepare_lock(state, anchor_path)
                    self._rewrite_anchor(
                        anchor_path,
                        manifest_digest="sha256:" + "a" * 64,
                    )
                    with mock.patch.object(
                        RECONCILER, "_recover_locked"
                    ) as recover, self.assertRaisesRegex(
                        RECONCILER.ReconcileError,
                        "RECONCILE_ANCHOR_INVALID",
                    ):
                        RECONCILER.reconcile(
                            state,
                            runner=mock.Mock(),
                            anchor_file=anchor_path,
                        )
                    recover.assert_not_called()
            finally:
                lock_path.unlink(missing_ok=True)

    def test_host_prerequisite_rejects_unsafe_ancestor_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            state, runtime, anchor_path = self._anchor_fixture(home)
            lock_path = RECONCILER._lock_path("reconcile-test")
            lock_path.unlink(missing_ok=True)
            try:
                home.chmod(0o770)
                with self._anchor_environment(home, runtime), self.assertRaisesRegex(
                    RECONCILER.ReconcileError, "RECONCILE_STATE_INVALID"
                ):
                    RECONCILER.prepare_lock(state, anchor_path)
                home.chmod(0o700)
                target = home / "target"
                target.mkdir(mode=0o700)
                link = home / "link"
                link.symlink_to(target, target_is_directory=True)
                with self.assertRaisesRegex(
                    RECONCILER.ReconcileError, "RECONCILE_STATE_INVALID"
                ):
                    RECONCILER._prove_host_directory(link)
            finally:
                home.chmod(0o700)
                lock_path.unlink(missing_ok=True)

    def test_prepare_proves_runtime_parent_before_any_anchor_write(self) -> None:
        for case in ("unsafe", "symlink", "replaced"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                home = Path(directory).resolve()
                state, runtime, anchor_path = self._anchor_fixture(home)
                lock_path = RECONCILER._lock_path("reconcile-test")
                lock_path.unlink(missing_ok=True)
                old_runtime = home / "runtime-old"
                pending_patch = contextlib.nullcontext()
                try:
                    if case == "unsafe":
                        runtime.chmod(0o770)
                    elif case == "symlink":
                        runtime.rename(old_runtime)
                        runtime.symlink_to(old_runtime, target_is_directory=True)
                    else:
                        real_pending = RECONCILER._pending_anchor

                        def replace_runtime(project):
                            pending = real_pending(project)
                            runtime.rename(old_runtime)
                            runtime.mkdir(mode=0o700)
                            return pending

                        pending_patch = mock.patch.object(
                            RECONCILER,
                            "_pending_anchor",
                            side_effect=replace_runtime,
                        )
                    with self._anchor_environment(home, runtime), pending_patch, self.assertRaisesRegex(
                        RECONCILER.ReconcileError,
                        "RECONCILE_(?:STATE|ANCHOR)_INVALID",
                    ):
                        RECONCILER.prepare_lock(state, anchor_path)
                    self.assertFalse(anchor_path.exists())
                    self.assertFalse(
                        (old_runtime / "tacua-reconcile.anchor.json").exists()
                    )
                finally:
                    lock_path.unlink(missing_ok=True)

    def test_config_inode_substitution_is_rejected_before_state_load(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            state, runtime, anchor_path = self._anchor_fixture(home)
            lock_path = RECONCILER._lock_path("reconcile-test")
            lock_path.unlink(missing_ok=True)
            try:
                with self._anchor_environment(home, runtime):
                    RECONCILER.prepare_lock(state, anchor_path)
                    config = home / "config.json"
                    replacement = home / "replacement-config.json"
                    replacement.write_bytes(config.read_bytes())
                    replacement.chmod(0o644)
                    replacement.replace(config)
                    with mock.patch.object(
                        RECONCILER,
                        "_load_bound_state",
                        side_effect=AssertionError(
                            "state was read before config binding rejection"
                        ),
                    ), self.assertRaisesRegex(
                        RECONCILER.ReconcileError,
                        "RECONCILE_ANCHOR_INVALID",
                    ):
                        RECONCILER._attested_lock(anchor_path, state)
            finally:
                lock_path.unlink(missing_ok=True)

    def test_safe_directory_overflow_requires_exact_attested_stop(self) -> None:
        euid = os.geteuid()
        state_binding = {
            "device": 10,
            "inode": 40,
            "mode": 0o700,
            "path": "/synthetic/home/state",
            "uid": euid,
        }
        records = [
            {"device": 1, "inode": 1, "mode": 0o755, "path": "/", "uid": 60001},
            {"device": 2, "inode": 2, "mode": 0o755, "path": "/synthetic", "uid": 60001},
            {"device": 3, "inode": 3, "mode": 0o700, "path": "/synthetic/home", "uid": euid},
            dict(state_binding),
            {"device": 10, "inode": 41, "mode": 0o700, "path": "/synthetic/home/state/child", "uid": euid},
        ]
        with mock.patch.object(
            RECONCILER, "_descriptor_directory_chain", return_value=records
        ):
            self.assertEqual(
                Path("/synthetic/home/state/child"),
                RECONCILER._safe_directory(
                    Path("/synthetic/home/state/child"),
                    attested_directories=(state_binding,),
                ),
            )
            mismatched = dict(state_binding, inode=99)
            with self.assertRaisesRegex(
                RECONCILER.ReconcileError, "RECONCILE_STATE_INVALID"
            ):
                RECONCILER._safe_directory(
                    Path("/synthetic/home/state/child"),
                    attested_directories=(mismatched,),
                )
            with self.assertRaisesRegex(
                RECONCILER.ReconcileError, "RECONCILE_STATE_INVALID"
            ):
                RECONCILER._safe_directory(
                    Path("/outside/anchor"),
                    attested_directories=(state_binding,),
                )

    def test_overflow_uid_matches_only_attested_root_owned_component(self) -> None:
        observed = {
            "device": 1,
            "inode": 2,
            "mode": 0o755,
            "path": "/synthetic",
            "uid": 60001,
        }
        root_owned = dict(observed, uid=0)
        unrelated_owner = dict(observed, uid=1234)
        current_owner = dict(observed, uid=os.geteuid())
        self.assertTrue(
            RECONCILER._record_matches_binding(
                observed,
                root_owned,
                overflow_uid=60001,
            )
        )
        self.assertFalse(
            RECONCILER._record_matches_binding(
                observed,
                unrelated_owner,
                overflow_uid=60001,
            )
        )
        self.assertFalse(
            RECONCILER._record_matches_binding(
                observed,
                current_owner,
                overflow_uid=60001,
            )
        )

    def test_anchor_shape_rejects_dot_and_dotdot_paths(self) -> None:
        self.assertIsNone(RECONCILER._canonical_absolute_path("/safe/./state"))
        self.assertIsNone(RECONCILER._canonical_absolute_path("/safe/../state"))
        self.assertIsNone(RECONCILER._canonical_absolute_path("/safe/\x00state"))
        binding = {
            "device": 1,
            "inode": 2,
            "mode": 0o700,
            "path": "/safe/../state",
            "uid": os.geteuid(),
        }
        self.assertFalse(
            RECONCILER._binding_valid(
                binding,
                mode=0o700,
                uid=os.geteuid(),
            )
        )

    def test_anchor_builder_rejects_namespace_incompatible_config_and_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            state, runtime, _anchor_path = self._anchor_fixture(home)
            desired, manifest, _compose = RECONCILER._load_bound_state(state)
            lock = {
                "device": 1,
                "inode": 2,
                "mode": 0o600,
                "path": str(RECONCILER._lock_path(desired["project"])),
                "uid": os.geteuid(),
            }
            for key in ("config", "secret"):
                with self.subTest(key=key), self._anchor_environment(home, runtime):
                    incompatible = dict(manifest)
                    incompatible[key] = dict(incompatible[key], uid=os.geteuid() + 1)
                    with mock.patch.object(
                        RECONCILER,
                        "_prove_host_directory",
                        side_effect=AssertionError(
                            "incompatible identity was not rejected early"
                        ),
                    ), self.assertRaisesRegex(
                        RECONCILER.ReconcileError,
                        "RECONCILE_ANCHOR_INVALID",
                    ):
                        RECONCILER._anchor_from_state(
                            desired,
                            incompatible,
                            state_directory=state,
                            lock=lock,
                        )

    def test_prepare_rejects_incompatible_inputs_before_pending_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            state, runtime, anchor_path = self._anchor_fixture(home)
            desired, manifest, compose = RECONCILER._load_bound_state(state)
            incompatible = dict(manifest)
            incompatible["secret"] = dict(
                incompatible["secret"],
                uid=os.geteuid() + 1,
            )
            with self._anchor_environment(home, runtime), mock.patch.object(
                RECONCILER,
                "_load_bound_state",
                return_value=(desired, incompatible, compose),
            ), self.assertRaisesRegex(
                RECONCILER.ReconcileError,
                "RECONCILE_ANCHOR_INVALID",
            ):
                RECONCILER.prepare_lock(state, anchor_path)
            self.assertFalse(anchor_path.exists())

    def test_user_descendant_ancestry_rejects_root_below_home(self) -> None:
        euid = os.geteuid()
        if euid == 0:
            self.skipTest("the rootless user-unit contract requires a non-root EUID")
        home_ancestry = [
            {"device": 1, "inode": 1, "mode": 0o755, "path": "/", "uid": 0},
            {
                "device": 1,
                "inode": 2,
                "mode": 0o700,
                "path": "/home/user",
                "uid": euid,
            },
        ]
        root_owned_child = [
            *home_ancestry,
            {
                "device": 1,
                "inode": 3,
                "mode": 0o755,
                "path": "/home/user/root-owned",
                "uid": 0,
            },
            {
                "device": 1,
                "inode": 4,
                "mode": 0o700,
                "path": "/home/user/root-owned/state",
                "uid": euid,
            },
        ]
        with self.assertRaisesRegex(
            RECONCILER.ReconcileError,
            "RECONCILE_ANCHOR_INVALID",
        ):
            RECONCILER._require_user_descendant_ancestry(
                root_owned_child,
                home_ancestry=home_ancestry,
            )
        compatible = [
            dict(record, uid=euid) if index >= len(home_ancestry) else record
            for index, record in enumerate(root_owned_child)
        ]
        RECONCILER._require_user_descendant_ancestry(
            compatible,
            home_ancestry=home_ancestry,
        )

    def test_anchor_swap_is_rejected_and_releases_same_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            state, runtime, anchor_path = self._anchor_fixture(home)
            lock_path = RECONCILER._lock_path("reconcile-test")
            lock_path.unlink(missing_ok=True)
            try:
                with self._anchor_environment(home, runtime):
                    RECONCILER.prepare_lock(state, anchor_path)
                    real_open = RECONCILER._open_host_lock

                    def swap_after_lock(path, *, create):
                        descriptor = real_open(path, create=create)
                        anchor_path.write_bytes(anchor_path.read_bytes() + b"\n")
                        return descriptor

                    with mock.patch.object(
                        RECONCILER,
                        "_open_host_lock",
                        side_effect=swap_after_lock,
                    ), self.assertRaisesRegex(
                        RECONCILER.ReconcileError,
                        "RECONCILE_ANCHOR_INVALID",
                    ):
                        RECONCILER._attested_lock(anchor_path, state)
                    descriptor = real_open(lock_path, create=False)
                    RECONCILER._release_lock(descriptor)
            finally:
                lock_path.unlink(missing_ok=True)

    def test_attested_main_never_recreates_missing_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            state, runtime, anchor_path = self._anchor_fixture(home)
            lock_path = RECONCILER._lock_path("reconcile-test")
            lock_path.unlink(missing_ok=True)
            with self._anchor_environment(home, runtime):
                RECONCILER.prepare_lock(state, anchor_path)
                lock_path.unlink()
                with self.assertRaisesRegex(
                    RECONCILER.ReconcileError,
                    "RECONCILE_LOCK_INVALID",
                ):
                    RECONCILER._attested_lock(anchor_path, state)
                self.assertFalse(lock_path.exists())

    def test_prepare_and_reconcile_cli_accept_exact_anchor_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            state, runtime, anchor_path = self._anchor_fixture(home)
            lock_path = RECONCILER._lock_path("reconcile-test")
            lock_path.unlink(missing_ok=True)
            previous_umask = os.umask(0o077)
            try:
                output = io.StringIO()
                with self._anchor_environment(home, runtime), contextlib.redirect_stdout(
                    output
                ):
                    self.assertEqual(
                        0,
                        RECONCILER.main(
                            [
                                "prepare-lock",
                                "--state-directory",
                                str(state),
                                "--anchor-file",
                                str(anchor_path),
                            ]
                        ),
                    )
                    with mock.patch.object(
                        RECONCILER,
                        "_runner_for_manifest",
                        return_value=mock.Mock(),
                    ):
                        self.assertEqual(
                            0,
                            RECONCILER.main(
                                [
                                    "reconcile",
                                    "--state-directory",
                                    str(state),
                                    "--anchor-file",
                                    str(anchor_path),
                                ]
                            ),
                        )
                lines = output.getvalue().splitlines()
                self.assertEqual(2, len(lines))
                self.assertEqual("healthy", json.loads(lines[0])["status"])
                self.assertEqual("maintenance", json.loads(lines[1])["status"])
            finally:
                os.umask(previous_umask)
                lock_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
