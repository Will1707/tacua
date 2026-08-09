# SPDX-License-Identifier: Apache-2.0
"""No-daemon safety tests for the rootless Docker backup integration harness."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "services" / "backend" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import reviewer_upgrade_backup_docker_integration as INTEGRATION  # noqa: E402


class FakeProcess:
    def __init__(self) -> None:
        self.docker_prefix = [
            "/usr/bin/docker",
            "--host",
            "unix:///run/user/1000/docker.sock",
        ]
        self.calls: list[tuple[list[str], int]] = []

    def __call__(self, argv: list[str], *, timeout: int) -> bytes:
        self.calls.append((list(argv), timeout))
        tail = argv[len(self.docker_prefix) :]
        if tail[:2] in (["container", "stop"], ["container", "start"]):
            return (tail[-1] + "\n").encode("ascii")
        if tail and tail[0] == "compose":
            return ("a" * 64 + "\n").encode("ascii")
        return b""


class IntegrationSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.names = INTEGRATION.LabNames.from_token("0123456789abcdef")
        self.process = FakeProcess()
        self.compose = self.names.root / "compose.json"
        self.backend_id = "a" * 64
        self.image_id = "sha256:" + "b" * 64
        self.gate = INTEGRATION.GuardedAdapterRunner(
            self.process,  # type: ignore[arg-type]
            self.names,
            self.compose,
            self.backend_id,
            self.image_id,
        )

    def _argv(self, tail: list[str]) -> list[str]:
        return [*self.process.docker_prefix, *tail]

    def _compose_ps(self, *, project: str | None = None) -> list[str]:
        return self._argv([
            "compose",
            "-p",
            project or self.names.project,
            "-f",
            str(self.compose),
            "ps",
            "--no-trunc",
            "-aq",
            "backend",
        ])

    def _archive_run(self, source: str) -> list[str]:
        tail = self.gate._expected_run(1, "archive")
        expected_bundle = (
            self.names.root
            / "upgrades"
            / self.names.operation_id
            / "backup-attempt-01"
            / "bundle"
        )
        mount = f"type=bind,src={expected_bundle},dst=/backup"
        tail[tail.index(mount)] = f"type=bind,src={source},dst=/backup"
        return self._argv(tail)

    def test_names_are_random_scope_compatible_and_never_production(self) -> None:
        self.assertEqual(self.names.project, "tacua_backup_e2e_0123456789abcdef")
        self.assertNotEqual(self.names.project, "tacua")
        self.assertRegex(self.names.image, r"^tacua-backend:e2e-[a-f0-9]{16}$")
        self.assertRegex(self.names.volume, r"^tacua-backup-e2e-[a-f0-9]{16}-state$")
        self.assertEqual(
            self.names.root,
            Path("/tmp/tacua-backup-e2e-0123456789abcdef"),
        )

    def test_compose_document_has_no_host_port_and_only_unique_resources(self) -> None:
        document = INTEGRATION._compose_document(
            self.names,
            self.names.root / "config.json",
            self.names.root / "admin-secret",
        )
        backend = document["services"]["backend"]
        self.assertNotIn("ports", backend)
        self.assertEqual(document["volumes"]["tacua-state"]["name"], self.names.volume)
        self.assertEqual(document["networks"]["lab"]["name"], self.names.network)
        self.assertTrue(document["networks"]["lab"]["internal"])
        self.assertEqual(backend["pull_policy"], "never")

    def test_gate_accepts_only_exact_compose_project_and_file(self) -> None:
        self.gate.authorize(self._compose_ps())
        with self.assertRaisesRegex(
            INTEGRATION.IntegrationError,
            "unexpected adapter Docker command",
        ):
            self.gate.authorize(self._compose_ps(project="tacua"))

    def test_gate_rejects_production_volume_query(self) -> None:
        argv = self._argv([
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            "volume=tacua_tacua-state",
        ])
        with self.assertRaisesRegex(
            INTEGRATION.IntegrationError,
            "queried an unowned Docker resource",
        ):
            self.gate.authorize(argv)

    def test_gate_rejects_mutation_of_another_container(self) -> None:
        argv = self._argv(["container", "start", "c" * 64])
        with self.assertRaisesRegex(
            INTEGRATION.IntegrationError,
            "unexpected adapter Docker command",
        ):
            self.gate.authorize(argv)

    def test_gate_accepts_timeout_and_rejects_deprecated_time_flag(self) -> None:
        auxiliary_id = "c" * 64
        self.gate.auxiliary_ids.add(auxiliary_id)
        accepted = (
            ["container", "stop", "--timeout", "30", self.backend_id],
            ["container", "stop", "--timeout", "10", auxiliary_id],
        )
        for tail in accepted:
            with self.subTest(accepted=tail):
                self.gate.authorize(self._argv(tail))

        deprecated = (
            ["container", "stop", "--time", "30", self.backend_id],
            ["container", "stop", "--time", "10", auxiliary_id],
        )
        for tail in deprecated:
            with self.subTest(deprecated=tail):
                with self.assertRaisesRegex(
                    INTEGRATION.IntegrationError,
                    "unexpected adapter Docker command",
                ):
                    self.gate.authorize(self._argv(tail))

    def test_gate_rejects_bind_mount_outside_lab_root(self) -> None:
        with self.assertRaisesRegex(
            INTEGRATION.IntegrationError,
            "escaped the exact lab grammar",
        ):
            self.gate.authorize(self._archive_run("/home/will/.tacua-reconcile"))

    def test_gate_rejects_dotdot_mount_and_every_docker_escape_alias(self) -> None:
        expected_bundle = (
            self.names.root
            / "upgrades"
            / self.names.operation_id
            / "backup-attempt-01"
            / "bundle"
        )
        dotdot = self._archive_run(
            str(self.names.root / "upgrades" / ".." / "production")
        )
        with self.assertRaisesRegex(
            INTEGRATION.IntegrationError,
            "escaped the exact lab grammar",
        ):
            self.gate.authorize(dotdot)

        exact = self._archive_run(str(expected_bundle))
        for option in (
            "--privileged=true",
            "--publish=127.0.0.1:1234:1234",
            "-P",
            "-v",
            "--network=host",
            "--device=/dev/sda",
            "--pid=host",
        ):
            with self.subTest(option=option):
                mutated = list(exact)
                mutated.insert(len(self.process.docker_prefix) + 1, option)
                with self.assertRaisesRegex(
                    INTEGRATION.IntegrationError,
                    "escaped the exact lab grammar",
                ):
                    self.gate.authorize(mutated)

    def test_gate_rejects_inexact_auxiliary_labels(self) -> None:
        expected_bundle = (
            self.names.root
            / "upgrades"
            / self.names.operation_id
            / "backup-attempt-01"
            / "bundle"
        )
        argv = self._archive_run(str(expected_bundle))
        index = argv.index(
            f"io.tacua.reviewer-upgrade.operation={self.names.operation_id}"
        )
        argv[index] = "io.tacua.reviewer-upgrade.operation=reviewer-production"
        with self.assertRaisesRegex(
            INTEGRATION.IntegrationError,
            "escaped the exact lab grammar",
        ):
            self.gate.authorize(argv)

    def test_gate_accepts_exact_owned_auxiliary_run(self) -> None:
        expected_bundle = (
            self.names.root
            / "upgrades"
            / self.names.operation_id
            / "backup-attempt-01"
            / "bundle"
        )
        argv = self._archive_run(str(expected_bundle))
        self.gate.authorize(argv)

    def test_exact_guard_grammar_matches_current_adapter_commands(self) -> None:
        adapter = object.__new__(INTEGRATION.docker_backup.DockerBackupRunner)
        adapter.bindings = SimpleNamespace(
            backend_image_id=self.image_id,
            config=SimpleNamespace(path=self.names.root / "config.json"),
            operation_id=self.names.operation_id,
            plan_digest=self.names.plan_digest,
            secret=SimpleNamespace(path=self.names.root / "admin-secret"),
            state_volume=self.names.volume,
        )
        adapter.manifest = {
            "commands": {"docker": self.process.docker_prefix[0]},
            "runtime": {"docker_host": self.process.docker_prefix[2]},
        }
        bundle = (
            self.names.root
            / "upgrades"
            / self.names.operation_id
            / "backup-attempt-01"
            / "bundle"
        )
        docker_prefix_length = len(self.process.docker_prefix)
        prepare = [
            *adapter._container_run_prefix(user="0:0", number=1, role="prepare"),
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "FOWNER",
            "--mount",
            f"type=bind,src={bundle},dst=/backup",
            "--entrypoint",
            "/bin/sh",
            self.image_id,
            "-ceu",
            adapter._prepare_script(),
        ][docker_prefix_length:]
        archive = [
            *adapter._container_run_prefix(
                user="10001:10001", number=1, role="archive"
            ),
            "--mount",
            f"type=volume,src={self.names.volume},dst=/var/lib/tacua",
            "--mount",
            (
                f"type=bind,src={self.names.root / 'config.json'},"
                "dst=/run/tacua/config.json,readonly"
            ),
            "--mount",
            (
                f"type=bind,src={self.names.root / 'admin-secret'},"
                "dst=/run/secrets/tacua_admin,readonly"
            ),
            "--mount",
            f"type=bind,src={bundle},dst=/backup",
            "--entrypoint",
            "/bin/sh",
            self.image_id,
            "-ceu",
            adapter._archive_script(),
        ][docker_prefix_length:]
        normalize = adapter._normalization_command(bundle, 1)[
            docker_prefix_length:
        ]
        verify = adapter._operator_verify_command(bundle, 1)[
            docker_prefix_length:
        ]

        self.assertEqual(self.gate._expected_run(1, "prepare"), prepare)
        self.assertEqual(self.gate._expected_run(1, "archive"), archive)
        self.assertEqual(self.gate._expected_run(1, "normalize"), normalize)
        self.assertEqual(self.gate._expected_run(1, "verify"), verify)

    def test_gate_rejects_missing_substituted_or_extra_normalize_capability(
        self,
    ) -> None:
        exact = self.gate._expected_run(1, "normalize")
        self.gate.authorize(self._argv(exact))
        capability_index = exact.index("DAC_READ_SEARCH")
        mutations = {
            "missing": (
                exact[: capability_index - 1]
                + exact[capability_index + 1 :]
            ),
            "substituted": (
                exact[:capability_index]
                + ["DAC_OVERRIDE"]
                + exact[capability_index + 1 :]
            ),
            "extra": (
                exact[: capability_index + 1]
                + ["--cap-add", "SYS_ADMIN"]
                + exact[capability_index + 1 :]
            ),
        }
        for name, tail in mutations.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    INTEGRATION.IntegrationError,
                    "escaped the exact lab grammar",
                ):
                    self.gate.authorize(self._argv(tail))

    def test_cleanup_normalizer_uses_the_same_minimal_capability(self) -> None:
        calls: list[tuple[list[str], int]] = []

        class CleanupProcess:
            def docker_call(
                inner_self,
                argv: list[str],
                *,
                timeout: int,
            ) -> bytes:
                calls.append((list(argv), timeout))
                return b""

        with (
            mock.patch.object(INTEGRATION, "_attest_lab_root"),
            mock.patch.object(INTEGRATION, "_assert_absent"),
        ):
            INTEGRATION._normalize_lab_tree(
                CleanupProcess(),  # type: ignore[arg-type]
                self.names,
                self.image_id,
                (1, 2),
            )

        self.assertEqual(len(calls), 1)
        argv, timeout = calls[0]
        self.assertEqual(timeout, 120)
        capabilities = [
            argv[index + 1]
            for index, value in enumerate(argv)
            if value == "--cap-add"
        ]
        self.assertEqual(
            capabilities,
            ["CHOWN", "DAC_READ_SEARCH", "FOWNER"],
        )
        self.assertNotIn("DAC_OVERRIDE", argv)

    def test_distinct_faults_cover_all_stop_and_start_boundaries(self) -> None:
        fault = INTEGRATION.FourBoundaryIndexFaultCommandRunner(self.gate)
        events: list[str] = []

        class FakeAdapter:
            bindings = type("Bindings", (), {"backend_container_id": self.backend_id})()

            def __call__(
                inner_self,
                action: str,
                _request: dict,
            ) -> dict[str, str]:
                if action == "stop_backend":
                    raw_stop = self._argv([
                        "container",
                        "stop",
                        "--timeout",
                        "30",
                        self.backend_id,
                    ])
                    self.assertEqual(
                        fault(raw_stop, timeout=45),
                        b"a" * 64 + b"\n",
                    )
                    events.append("raw_stop_return")
                    events.append("internal_stop_inspect")
                    self.assertEqual(
                        fault(self._compose_ps(), timeout=30),
                        b"",
                    )
                    self.assertEqual(
                        fault(self._compose_ps(), timeout=30),
                        b"a" * 64 + b"\n",
                    )
                    events.append("stop_return")
                    return {
                        "container_id": self.backend_id,
                        "status": "stopped",
                    }
                if action == "start_backend":
                    raw_start = self._argv([
                        "container",
                        "start",
                        self.backend_id,
                    ])
                    self.assertEqual(
                        fault(raw_start, timeout=30),
                        b"a" * 64 + b"\n",
                    )
                    events.append("raw_start_return")
                    events.append("internal_start_inspect")
                    self.assertEqual(
                        fault(self._compose_ps(), timeout=30),
                        b"",
                    )
                    self.assertEqual(
                        fault(self._compose_ps(), timeout=30),
                        b"a" * 64 + b"\n",
                    )
                    events.append("start_return")
                    return {
                        "container_id": self.backend_id,
                        "status": "started",
                    }
                events.append("public_inspect")
                self.assertEqual(
                    fault(self._compose_ps(), timeout=30),
                    b"",
                )
                self.assertEqual(
                    fault(self._compose_ps(), timeout=30),
                    b"a" * 64 + b"\n",
                )
                return {"status": "observed"}

        action_runner = INTEGRATION.PostActionBoundaryRunner(
            FakeAdapter(),  # type: ignore[arg-type]
            fault,
        )
        self.assertEqual(
            action_runner("stop_backend", {}),
            {"container_id": self.backend_id, "status": "stopped"},
        )
        self.assertEqual(
            events,
            ["raw_stop_return", "internal_stop_inspect", "stop_return"],
        )
        self.assertEqual(fault.internal_stop_injections, 1)
        self.assertEqual(fault.public_stop_injections, 0)
        self.assertTrue(action_runner.armed_after_stop_return)
        self.assertEqual(action_runner.completed_stop_actions, 1)

        action_runner("inspect_backend", {})
        self.assertEqual(events[-1], "public_inspect")
        self.assertEqual(fault.internal_stop_injections, 1)
        self.assertEqual(fault.public_stop_injections, 1)

        self.assertEqual(
            action_runner("start_backend", {}),
            {"container_id": self.backend_id, "status": "started"},
        )
        self.assertEqual(
            events[-3:],
            ["raw_start_return", "internal_start_inspect", "start_return"],
        )
        self.assertEqual(fault.internal_start_injections, 1)
        self.assertEqual(fault.public_start_injections, 0)
        self.assertTrue(action_runner.armed_after_start_return)
        self.assertEqual(action_runner.completed_start_actions, 1)

        action_runner("inspect_backend", {})
        self.assertEqual(events[-1], "public_inspect")
        self.assertEqual(fault.internal_start_injections, 1)
        self.assertEqual(fault.public_start_injections, 1)
        self.assertEqual(fault.injections, 4)
        self.assertIsNone(fault.armed_boundary)
        self.assertEqual(
            fault(self._compose_ps(), timeout=30),
            b"a" * 64 + b"\n",
        )

    def test_ownership_attestation_requires_both_exact_labels(self) -> None:
        document = [{
            "Labels": {
                INTEGRATION.OWNER_LABEL: INTEGRATION.OWNER_VALUE,
                INTEGRATION.RUN_LABEL: self.names.token,
            }
        }]
        self.assertTrue(INTEGRATION._owned_labels(document, self.names))
        document[0]["Labels"][INTEGRATION.RUN_LABEL] = "fedcba9876543210"
        self.assertFalse(INTEGRATION._owned_labels(document, self.names))

    def test_smoke_binding_guard_rejects_each_substitution(self) -> None:
        config = self.names.root / "config.json"
        secret = self.names.root / "admin-secret"
        origin = "http://127.0.0.1:65535"
        INTEGRATION._assert_smoke_bindings(
            config,
            secret,
            origin,
            expected_config=config,
            expected_secret=secret,
            expected_origin=origin,
        )
        substitutions = (
            (Path("/tmp/production-config.json"), secret, origin),
            (config, Path("/tmp/production-secret"), origin),
            (config, secret, "http://127.0.0.1:8080"),
        )
        for selected in substitutions:
            with self.subTest(selected=selected):
                with self.assertRaisesRegex(
                    INTEGRATION.IntegrationError,
                    "smoke escaped the exact lab bindings",
                ):
                    INTEGRATION._assert_smoke_bindings(
                        *selected,
                        expected_config=config,
                        expected_secret=secret,
                        expected_origin=origin,
                    )

    def test_failed_docker_cleanup_retains_exact_lab_evidence(self) -> None:
        names = INTEGRATION.LabNames.fresh()
        names.root.mkdir(mode=0o700)
        self.addCleanup(
            lambda: shutil.rmtree(names.root) if names.root.exists() else None
        )
        metadata = names.root.lstat()
        identity = (metadata.st_dev, metadata.st_ino)

        removed = INTEGRATION._remove_lab_root_after_docker_cleanup(
            names,
            identity,
            docker_cleanup_failed=True,
        )
        self.assertFalse(removed)
        self.assertTrue(names.root.is_dir())

        removed = INTEGRATION._remove_lab_root_after_docker_cleanup(
            names,
            identity,
            docker_cleanup_failed=False,
            retain_evidence=True,
        )
        self.assertFalse(removed)
        self.assertTrue(names.root.is_dir())

    def test_primary_failure_cleanup_retains_the_attested_lab_root(self) -> None:
        names = INTEGRATION.LabNames.fresh()
        names.root.mkdir(mode=0o700)
        self.addCleanup(
            lambda: shutil.rmtree(names.root) if names.root.exists() else None
        )
        metadata = names.root.lstat()
        identity = (metadata.st_dev, metadata.st_ino)

        with mock.patch.object(
            INTEGRATION,
            "_listed_resource",
            return_value=[],
        ):
            INTEGRATION._cleanup(
                self.process,  # type: ignore[arg-type]
                names,
                None,
                None,
                None,
                identity,
                retain_evidence=True,
            )

        self.assertTrue(names.root.is_dir())
        self.assertEqual(
            (names.root.lstat().st_dev, names.root.lstat().st_ino),
            identity,
        )

    def test_failure_diagnostic_uses_only_allowlisted_stage_and_cause(self) -> None:
        docker_error = INTEGRATION.docker_backup.DockerBackupError(
            INTEGRATION.docker_backup._ACTION_FAILED
        )
        action_error = INTEGRATION.backup._ActionError("inspect_backend")
        action_error.__cause__ = docker_error
        primary = INTEGRATION.backup.BackupError(
            INTEGRATION.backup._FAILED
        )
        primary.__cause__ = action_error

        document = INTEGRATION._failure_document(
            "run_backup",
            primary,
            cleanup_status="complete",
        )

        self.assertEqual(document, {
            "cause_chain": [
                "stable_code:REVIEWER_UPGRADE_BACKUP_FAILED",
                "backup_action:inspect_backend",
                (
                    "stable_code:"
                    "REVIEWER_UPGRADE_BACKUP_DOCKER_ACTION_FAILED"
                ),
            ],
            "cleanup_status": "complete",
            "contract_version": INTEGRATION.FAILURE_CONTRACT,
            "stage": "run_backup",
            "status": "failed",
        })
        serialized = INTEGRATION._canonical(document)
        self.assertNotIn(b"/tmp/", serialized)
        self.assertLessEqual(len(serialized), 2_048)

        sensitive = INTEGRATION.IntegrationError(
            "secret=/tmp/private command output"
        )
        sanitized = INTEGRATION._canonical(
            INTEGRATION._failure_document(
                "start_backend",
                sensitive,
                cleanup_status="incomplete",
            )
        )
        self.assertNotIn(b"secret", sanitized)
        self.assertNotIn(b"/tmp/private", sanitized)
        self.assertIn(b'integration_error', sanitized)

    def test_failure_record_is_private_canonical_and_path_free(self) -> None:
        canonical_tmp = Path("/tmp").resolve()
        with mock.patch.object(
            INTEGRATION,
            "LAB_ROOT_PARENT",
            canonical_tmp,
        ):
            names = INTEGRATION.LabNames.fresh()
            names.root.mkdir(mode=0o700)
            self.addCleanup(
                lambda: (
                    shutil.rmtree(names.root)
                    if names.root.exists()
                    else None
                )
            )
            metadata = names.root.lstat()
            identity = (metadata.st_dev, metadata.st_ino)
            document = INTEGRATION._failure_document(
                "build_image",
                INTEGRATION.IntegrationError("arbitrary private detail"),
                cleanup_status="complete",
            )

            INTEGRATION._write_failure_record(names, identity, document)

            record = names.root / INTEGRATION.FAILURE_FILE
            self.assertEqual(record.read_bytes(), INTEGRATION._canonical(document))
            self.assertEqual(record.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(str(names.root).encode(), record.read_bytes())

    def test_result_serialization_cannot_emit_nan(self) -> None:
        self.assertEqual(
            json.loads(INTEGRATION._canonical({"status": "ok"})),
            {"status": "ok"},
        )


if __name__ == "__main__":
    unittest.main()
