# SPDX-License-Identifier: Apache-2.0
"""No-daemon contracts for the reviewer-upgrade prepublication launcher."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import fcntl
import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "services/backend/scripts"
TEMPLATES = ROOT / "services/backend/systemd"
import sys

sys.path.insert(0, str(SCRIPTS))

import reviewer_upgrade_bootstrap as BOOTSTRAP  # noqa: E402
import reviewer_upgrade_candidate as CANDIDATE  # noqa: E402
import reviewer_upgrade_candidate_build as CANDIDATE_BUILD  # noqa: E402
import reviewer_upgrade_journal as JOURNAL  # noqa: E402
import reviewer_upgrade_launcher as LAUNCHER  # noqa: E402
import reviewer_upgrade_transaction as TRANSACTION  # noqa: E402


PLAN_DIGEST = "sha256:" + "a" * 64
REAL_LOAD_PREPARED_RELEASE = CANDIDATE.load_prepared_release


class InjectedCrash(RuntimeError):
    pass


class ReviewerUpgradeLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.prepared_releases = {}

        def load(release_root, **_kwargs):
            return self.prepared_releases[release_root]

        loader = mock.patch.object(
            LAUNCHER.prepared_candidate,
            "load_prepared_release",
            side_effect=load,
            create=True,
        )
        self.release_loader = loader.start()
        self.addCleanup(loader.stop)

    def _build_real_prepared_release(self, base: Path):
        base = base.resolve()
        base.chmod(0o700)
        installed = base / "installed"
        state = base / "state"
        preparations = base / "preparations"
        binaries = base / "producer-bin"
        for directory in (installed, state, preparations, binaries):
            directory.mkdir(mode=0o700)
        tools = {}
        for name in ("git", "python3", "node", "docker", "bash"):
            path = binaries / name
            path.write_bytes(b"#!/bin/sh\nexit 0\n")
            path.chmod(0o700)
            tools[name] = path
        npm_cli = binaries / "npm-cli.js"
        npm_cli.write_bytes(b"process.exit(0);\n")
        npm_cli.chmod(0o600)
        build_inputs = CANDIDATE_BUILD.BuildInputs(
            installed_repository=installed,
            installed_commit="1" * 40,
            candidate_commit="2" * 40,
            source_state_directory=state,
            preparations_parent=preparations,
            repository_identity="Will1707/tacua",
            git=tools["git"],
            python=tools["python3"],
            node=tools["node"],
            npm_cli=npm_cli,
            docker=tools["docker"],
            bash=tools["bash"],
            command_path=str(binaries),
        )
        old_ingress = (
            installed / "services/backend/ingress/haproxy.cfg"
        )
        old_ingress.parent.mkdir(parents=True, mode=0o700)
        old_ingress.write_bytes(b"global\n  daemon\n")
        source_document = {
            "configs": {
                "tacua_loopback_ingress": {"file": str(old_ingress)}
            },
            "services": {
                "backend": {
                    "build": {"context": str(installed)},
                    "image": "tacua-backend:old",
                },
                "reviewer": {
                    "build": {"context": str(installed)},
                    "image": "tacua-reviewer-web:old",
                },
            },
        }
        generation = state / "generations" / "generation-one"
        generation.mkdir(parents=True, mode=0o700)
        source_compose = generation / "compose.json"
        source_payload = CANDIDATE_BUILD._canonical_json(source_document)
        source_compose.write_bytes(source_payload)
        source_compose.chmod(0o400)
        home = base / "home"
        xdg = base / "xdg"
        home.mkdir(mode=0o700)
        xdg.mkdir(mode=0o700)
        source_digest = CANDIDATE_BUILD._digest(source_payload)
        producer_state = (
            {"compose_digest": source_digest, "desired": "running"},
            {
                "commands": {"docker": str(build_inputs.docker)},
                "compose_digest": source_digest,
                "runtime": {
                    "docker_host": "unix:///private/docker.sock",
                    "home": str(home),
                    "xdg_runtime_directory": str(xdg),
                },
            },
            source_compose,
            source_payload,
            source_document,
        )

        def materialize_checkout(checkout: Path) -> None:
            checkout.mkdir(mode=0o700)
            for relative in sorted(CANDIDATE.REQUIRED_RUNTIME_FILES):
                path = checkout / relative
                path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                template_names = set(BOOTSTRAP.TEMPLATE_NAMES.values())
                if relative.startswith("services/backend/systemd/") and (
                    Path(relative).name in template_names
                ):
                    payload = (
                        TEMPLATES / Path(relative).name
                    ).read_bytes()
                elif relative == (
                    "services/backend/scripts/"
                    "reviewer_upgrade_transaction.py"
                ):
                    payload = (
                        SCRIPTS / "reviewer_upgrade_transaction.py"
                    ).read_bytes()
                elif relative == "services/backend/ingress/haproxy.cfg":
                    payload = b"global\n  daemon\n"
                else:
                    payload = f"# retained fixture: {relative}\n".encode()
                path.write_bytes(payload)
                path.chmod(0o600)

        index = b"".join(
            b"100644 "
            + b"a" * 40
            + b" 0\t"
            + relative.encode("ascii")
            + b"\0"
            for relative in sorted(CANDIDATE.REQUIRED_RUNTIME_FILES)
        )
        image_id = "sha256:" + "a" * 64
        responses = {
            "node-version": CANDIDATE_BUILD.CommandResult(
                0,
                f"{CANDIDATE_BUILD.REQUIRED_NODE_VERSION}\n".encode(),
            ),
            "npm-version": CANDIDATE_BUILD.CommandResult(
                0,
                f"{CANDIDATE_BUILD.REQUIRED_NPM_VERSION}\n".encode(),
            ),
            "installed-root": CANDIDATE_BUILD.CommandResult(
                0, f"{installed}\n".encode()
            ),
            "installed-head": CANDIDATE_BUILD.CommandResult(
                0, f"{build_inputs.installed_commit}\n".encode()
            ),
            "installed-origin": CANDIDATE_BUILD.CommandResult(
                0, f"{build_inputs.repository_url}\n".encode()
            ),
            "candidate-fetch-head": CANDIDATE_BUILD.CommandResult(
                0, f"{build_inputs.candidate_commit}\n".encode()
            ),
            "candidate-origin": CANDIDATE_BUILD.CommandResult(
                0, f"{build_inputs.repository_url}\n".encode()
            ),
            "candidate-head": CANDIDATE_BUILD.CommandResult(
                0, f"{build_inputs.candidate_commit}\n".encode()
            ),
            "candidate-restricted-diff": CANDIDATE_BUILD.CommandResult(
                0,
                b"services/backend/scripts/"
                b"reviewer_upgrade_transaction.py\0",
            ),
            "candidate-index": CANDIDATE_BUILD.CommandResult(0, index),
            "reviewer-image-absent": CANDIDATE_BUILD.CommandResult(1),
            "backend-image-absent": CANDIDATE_BUILD.CommandResult(1),
            "reviewer-image-id": CANDIDATE_BUILD.CommandResult(
                0, f"{image_id}\n".encode()
            ),
            "reviewer-image-reproof": CANDIDATE_BUILD.CommandResult(
                0, f"{image_id}\n".encode()
            ),
            "installed-head-reproof": CANDIDATE_BUILD.CommandResult(
                0, f"{build_inputs.installed_commit}\n".encode()
            ),
        }

        class Runner:
            def __call__(self, argv, **kwargs):
                if kwargs["label"] == "candidate-clone":
                    materialize_checkout(Path(argv[-1]))
                return responses.get(
                    kwargs["label"],
                    CANDIDATE_BUILD.CommandResult(),
                )

        with mock.patch.object(
            CANDIDATE_BUILD,
            "_read_source_compose",
            return_value=producer_state,
        ), mock.patch.object(
            CANDIDATE_BUILD,
            "_allocate_test_port",
            return_value=49152,
        ):
            previous_loader = self.release_loader.side_effect
            self.release_loader.side_effect = REAL_LOAD_PREPARED_RELEASE
            try:
                prepared = CANDIDATE_BUILD.build_prepared_release(
                    build_inputs,
                    runner=Runner(),
                )
            finally:
                self.release_loader.side_effect = previous_loader
        return prepared, build_inputs, producer_state, home, xdg

    def _fixture(self, base: Path, *, marker: str = "one"):
        base = base.resolve()
        base.chmod(0o700)
        release_id = hashlib.sha256(marker.encode("ascii")).hexdigest()
        release_root = base / "releases" / release_id
        release_root.mkdir(mode=0o700, parents=True)
        repository = release_root / "source"
        template_directory = repository / "services/backend/systemd"
        script_directory = repository / "services/backend/scripts"
        template_directory.mkdir(mode=0o700, parents=True)
        script_directory.mkdir(mode=0o700)
        for name in BOOTSTRAP.TEMPLATE_NAMES.values():
            target = template_directory / name
            shutil.copyfile(TEMPLATES / name, target)
            target.chmod(0o600)
        upgrader = script_directory / "reviewer_upgrade_transaction.py"
        upgrader.write_bytes(
            (SCRIPTS / "reviewer_upgrade_transaction.py").read_bytes()
            + f"\n# {marker}\n".encode("ascii")
        )
        upgrader.chmod(0o700)
        state_parent = base / "state-parent"
        state_parent.mkdir(mode=0o700, exist_ok=True)
        state = state_parent / "sealed-state"
        state.mkdir(mode=0o700, exist_ok=True)
        units = base / "units"
        units.mkdir(mode=0o700, exist_ok=True)
        operations = base / "operations"
        operations.mkdir(mode=0o700, exist_ok=True)
        home = base / "home"
        home.mkdir(mode=0o700, exist_ok=True)
        runtime = base / "runtime"
        runtime.mkdir(mode=0o700, exist_ok=True)
        config = base / "config.json"
        config.write_bytes(b"{}")
        config.chmod(0o600)
        secret = base / "admin-secret"
        secret.write_bytes(b"secret\n")
        secret.chmod(0o600)
        candidate = release_root / "candidate-compose.json"
        candidate.write_bytes(
            JOURNAL.canonical_json(
                {
                    "services": {
                        "reviewer": {"image": f"tacua-reviewer-web:{marker}"}
                    }
                }
            )
        )
        candidate.chmod(0o600)
        binaries = base / "bin"
        binaries.mkdir(mode=0o700, exist_ok=True)
        python = binaries / "python3"
        systemctl = binaries / "systemctl"
        systemd_analyze = binaries / "systemd-analyze"
        for binary in (python, systemctl, systemd_analyze):
            binary.write_bytes(b"#!/bin/sh\nexit 0\n")
            binary.chmod(0o700)
        project = "launcher-test"
        inputs = LAUNCHER.LaunchInputs(
            release_root=release_root,
            repository=repository,
            state_directory=state,
            candidate_compose=candidate,
            unit_directory=units,
            lock_file=TRANSACTION.reconciler._lock_path(project),
            operation_directory=operations,
            serial_lock_file=state_parent / TRANSACTION.SERIAL_LOCK_FILE,
            config_file=config,
            admin_secret_file=secret,
            python=python,
            systemctl=systemctl,
            systemd_analyze=systemd_analyze,
            home=home,
            xdg_runtime_directory=runtime,
            project=project,
        )
        digest = lambda label: "sha256:" + hashlib.sha256(
            f"{marker}:{label}".encode("ascii")
        ).hexdigest()
        python_metadata = python.lstat()
        prepared_python = {
            "device": python_metadata.st_dev,
            "digest": "sha256:" + hashlib.sha256(python.read_bytes()).hexdigest(),
            "inode": python_metadata.st_ino,
            "mode": stat.S_IMODE(python_metadata.st_mode),
            "path": str(python),
            "uid": python_metadata.st_uid,
        }
        compose = state / "compose.json"
        source_compose_digest = digest("source-compose")
        self.prepared_releases[release_root] = SimpleNamespace(
            release_root=release_root,
            repository=repository,
            candidate_compose=candidate,
            receipt={
                "receipt_digest": digest("preparation"),
                "reviewer_image": {
                    "id": digest("reviewer-image"),
                    "ref": f"tacua-reviewer-web:{marker}",
                },
                "source_compose": {
                    "digest": source_compose_digest,
                    "mode": 0o400,
                    "path": str(compose),
                },
                "tools": {"python": prepared_python},
            },
            source_manifest={
                "manifest_digest": digest("manifest"),
                "runtime_closure": {
                    "closure_digest": digest("closure"),
                },
                "tree_digest": digest("tree"),
            },
        )
        desired = {"desired": "running", "project": project}
        manifest = {
            "compose_digest": source_compose_digest,
            "config": {"path": str(config)},
            "operation_directory": str(operations),
            "project": project,
            "secret": {"path": str(secret)},
        }
        return inputs, (desired, manifest, compose)

    def _target(self, inputs):
        return BOOTSTRAP.render_stable_unit_bundle(
            inputs.template_directory,
            inputs.stable_bindings(),
        )

    def _install_target(self, inputs):
        target = self._target(inputs)
        for artifact in target.units:
            path = inputs.unit_directory / artifact.name
            path.write_bytes(artifact.payload)
            path.chmod(0o600)
        return target

    def _bootstrap(self, inputs, *, fail_after=None, seen=None):
        def invoke(
            template_directory,
            bindings,
            old,
            commands,
            runner,
            *,
            serial_descriptor,
            serial_binding,
            path_deadline_seconds,
            target_bundle,
            **_unused,
        ):
            del old, commands, runner, serial_binding, path_deadline_seconds
            pending = inputs.stable_state / LAUNCHER.PENDING_FILE
            self.assertTrue(pending.is_file())
            probe = os.open(inputs.serial_lock_file, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(probe)
            if seen is not None:
                seen.append(serial_descriptor)
            target = BOOTSTRAP.render_stable_unit_bundle(
                template_directory,
                bindings,
            )
            self.assertEqual(target_bundle, target)
            target = target_bundle
            for index, artifact in enumerate(target.units, start=1):
                path = inputs.unit_directory / artifact.name
                path.write_bytes(artifact.payload)
                path.chmod(0o600)
                if fail_after == index:
                    raise BOOTSTRAP.BootstrapError(
                        "UPGRADE_BOOTSTRAP_INSTALL_FAILED"
                    )
            return LAUNCHER._expected_bootstrap_receipt(target, bindings)

        return invoke

    def _prepare(
        self,
        inputs,
        *,
        seen=None,
        fail=None,
        operation_id="reviewer-launch-test",
    ):
        def invoke(*_args, **kwargs):
            descriptor = kwargs["serial_lock_descriptor"]
            reviewer_image = self.prepared_releases[
                inputs.release_root
            ].receipt["reviewer_image"]
            self.assertEqual(
                kwargs["expected_candidate_image_ref"],
                reviewer_image["ref"],
            )
            self.assertEqual(
                kwargs["expected_candidate_image_id"],
                reviewer_image["id"],
            )
            if seen is not None:
                seen.append(descriptor)
            probe = os.open(inputs.serial_lock_file, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(probe)
            target = self._target(inputs)
            self.assertTrue(
                all(
                    (inputs.unit_directory / item.name).read_bytes()
                    == item.payload
                    for item in target.units
                )
            )
            self.assertFalse(
                (inputs.stable_state / LAUNCHER.PENDING_FILE).exists()
            )
            current = LAUNCHER._load_current(
                inputs.stable_state,
                inputs.stable_state / LAUNCHER.SNAPSHOTS_DIRECTORY,
            )
            self.assertIsNotNone(current)
            self.assertEqual(current[3], target)
            if fail is not None:
                raise fail
            upgrades = TRANSACTION._ensure_upgrades_directory(
                inputs.state_parent
            )
            TRANSACTION._publish_active(upgrades, operation_id, PLAN_DIGEST)
            return {
                "code": "REVIEWER_UPGRADE_PREPARED",
                "operation_id": operation_id,
                "phase": TRANSACTION.QUIESCING,
                "status": "quiescing",
            }

        return invoke

    def _launch(self, inputs, state, **patches):
        bootstrap_side_effect = patches.pop(
            "bootstrap_side_effect",
            self._bootstrap(inputs),
        )
        prepare_side_effect = patches.pop(
            "prepare_side_effect",
            self._prepare(inputs),
        )
        with mock.patch.object(
            LAUNCHER.reconciler,
            "_load_bound_state",
            return_value=state,
        ), mock.patch.object(
            LAUNCHER.bootstrap,
            "_bootstrap_prepublication_locked",
            side_effect=bootstrap_side_effect,
        ) as bootstrap_call, mock.patch.object(
            LAUNCHER.transaction,
            "prepare",
            side_effect=prepare_side_effect,
        ) as prepare_call, mock.patch.object(
            LAUNCHER,
            "_prove_prepared_plan",
            return_value=PLAN_DIGEST,
        ):
            result = LAUNCHER.launch(inputs, **patches)
        return result, bootstrap_call, prepare_call

    def test_first_install_arms_before_prepare_and_persists_exact_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))
            order = []
            result, bootstrap_call, prepare_call = self._launch(
                inputs,
                state,
                current_units="absent",
                bootstrap_side_effect=self._bootstrap(inputs, seen=order),
                prepare_side_effect=self._prepare(inputs, seen=order),
            )

            self.assertEqual(result["code"], LAUNCHER.LAUNCH_CODE)
            self.assertEqual(len(order), 2)
            self.assertEqual(order[0], order[1])
            bootstrap_call.assert_called_once()
            prepare_call.assert_called_once()
            current = LAUNCHER._load_current(
                inputs.stable_state,
                inputs.stable_state / LAUNCHER.SNAPSHOTS_DIRECTORY,
            )
            self.assertIsNotNone(current)
            self.assertEqual(current[3], self._target(inputs))
            prepared = self.prepared_releases[inputs.release_root]
            binding = current[2]["launch_binding"]
            self.assertEqual(
                binding["preparation_receipt_digest"],
                prepared.receipt["receipt_digest"],
            )
            self.assertEqual(
                binding["source_manifest_digest"],
                prepared.source_manifest["manifest_digest"],
            )
            self.assertEqual(
                binding["source_tree_digest"],
                prepared.source_manifest["tree_digest"],
            )
            self.assertEqual(
                binding["runtime_closure_digest"],
                prepared.source_manifest["runtime_closure"][
                    "closure_digest"
                ],
            )
            self.assertEqual(
                binding["release_root_path"],
                str(inputs.release_root),
            )
            self.assertEqual(
                binding["prepared_reviewer_image_ref"],
                prepared.receipt["reviewer_image"]["ref"],
            )
            self.assertEqual(
                binding["prepared_reviewer_image_id"],
                prepared.receipt["reviewer_image"]["id"],
            )
            self.assertEqual(
                binding["prepared_source_compose_path"],
                prepared.receipt["source_compose"]["path"],
            )
            self.assertEqual(
                binding["prepared_source_compose_digest"],
                prepared.receipt["source_compose"]["digest"],
            )
            self.assertTrue(inputs.release_root.is_dir())
            self.assertEqual(self.release_loader.call_count, 2)
            receipt = (
                inputs.stable_state
                / LAUNCHER.PREPARATIONS_DIRECTORY
                / "reviewer-launch-test.json"
            )
            self.assertTrue(receipt.is_file())
            self.assertFalse(
                (inputs.stable_state / LAUNCHER.PENDING_FILE).exists()
            )

    def test_real_producer_loader_and_launcher_handoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            (
                prepared,
                build_inputs,
                producer_state,
                home,
                xdg,
            ) = self._build_real_prepared_release(base)
            units = base / "launcher-units"
            operations = base / "launcher-operations"
            operator_inputs = base / "operator-inputs"
            for directory in (units, operations, operator_inputs):
                directory.mkdir(mode=0o700)
            config = operator_inputs / "config.json"
            secret = operator_inputs / "admin-secret"
            config.write_bytes(b"{}")
            secret.write_bytes(b"synthetic-secret\n")
            config.chmod(0o600)
            secret.chmod(0o600)
            systemctl = build_inputs.git.parent / "systemctl"
            systemd_analyze = build_inputs.git.parent / "systemd-analyze"
            for binary in (systemctl, systemd_analyze):
                binary.write_bytes(b"#!/bin/sh\nexit 0\n")
                binary.chmod(0o700)
            project = "launcher-real-release"
            _producer_desired, _producer_manifest, compose, _, _ = (
                producer_state
            )
            state = build_inputs.source_state_directory
            inputs = LAUNCHER.LaunchInputs(
                release_root=prepared.release_root,
                repository=prepared.repository,
                state_directory=state,
                candidate_compose=prepared.candidate_compose,
                unit_directory=units,
                lock_file=TRANSACTION.reconciler._lock_path(project),
                operation_directory=operations,
                serial_lock_file=(
                    state.parent / TRANSACTION.SERIAL_LOCK_FILE
                ),
                config_file=config,
                admin_secret_file=secret,
                python=build_inputs.python,
                systemctl=systemctl,
                systemd_analyze=systemd_analyze,
                home=home,
                xdg_runtime_directory=xdg,
                project=project,
            )
            source_digest = prepared.receipt["source_compose"]["digest"]
            bound_state = (
                {"desired": "running", "project": project},
                {
                    "compose_digest": source_digest,
                    "config": {"path": str(config)},
                    "operation_directory": str(operations),
                    "project": project,
                    "secret": {"path": str(secret)},
                },
                compose,
            )
            self.prepared_releases[prepared.release_root] = prepared
            self.release_loader.reset_mock()
            self.release_loader.side_effect = REAL_LOAD_PREPARED_RELEASE

            result, bootstrap_call, prepare_call = self._launch(
                inputs,
                bound_state,
                current_units="absent",
            )

            self.assertEqual(result["code"], LAUNCHER.LAUNCH_CODE)
            bootstrap_call.assert_called_once()
            prepare_call.assert_called_once()
            self.assertEqual(self.release_loader.call_count, 2)
            current = LAUNCHER._load_current(
                inputs.stable_state,
                inputs.stable_state / LAUNCHER.SNAPSHOTS_DIRECTORY,
            )
            self.assertIsNotNone(current)
            self.assertEqual(
                current[2]["launch_binding"][
                    "preparation_receipt_digest"
                ],
                prepared.receipt["receipt_digest"],
            )
            self.assertEqual(
                current[2]["launch_binding"][
                    "prepared_reviewer_image_id"
                ],
                prepared.receipt["reviewer_image"]["id"],
            )

    def test_prepared_release_paths_must_equal_explicit_launcher_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))
            prepared = self.prepared_releases[inputs.release_root]
            self.prepared_releases[inputs.release_root] = SimpleNamespace(
                **{
                    **prepared.__dict__,
                    "repository": inputs.release_root / "different-source",
                }
            )
            with mock.patch.object(
                LAUNCHER.reconciler,
                "_load_bound_state",
                return_value=state,
            ), mock.patch.object(
                LAUNCHER.bootstrap,
                "_bootstrap_prepublication_locked",
            ) as bootstrap_call, mock.patch.object(
                LAUNCHER.transaction,
                "prepare",
            ) as prepare_call:
                with self.assertRaisesRegex(
                    LAUNCHER.LauncherError,
                    "REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID",
                ):
                    LAUNCHER.launch(inputs, current_units="absent")
            bootstrap_call.assert_not_called()
            prepare_call.assert_not_called()

    def test_candidate_validation_failure_is_a_stable_launcher_failure(self):
        class SyntheticCandidateError(RuntimeError):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))
            self.release_loader.side_effect = SyntheticCandidateError(
                "content-specific detail"
            )
            with mock.patch.object(
                LAUNCHER.prepared_candidate,
                "CandidateError",
                SyntheticCandidateError,
                create=True,
            ), mock.patch.object(
                LAUNCHER.reconciler,
                "_load_bound_state",
                return_value=state,
            ), mock.patch.object(
                LAUNCHER.bootstrap,
                "_bootstrap_prepublication_locked",
            ) as bootstrap_call, mock.patch.object(
                LAUNCHER.transaction,
                "prepare",
            ) as prepare_call:
                with self.assertRaisesRegex(
                    LAUNCHER.LauncherError,
                    "REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID",
                ):
                    LAUNCHER.launch(inputs, current_units="absent")
            bootstrap_call.assert_not_called()
            prepare_call.assert_not_called()

    def test_prepared_source_compose_must_match_selected_generation(self):
        cases = ("different-generation", "different-digest")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                inputs, state = self._fixture(Path(temporary))
                desired, manifest, compose = state
                prepared = self.prepared_releases[inputs.release_root]
                receipt = deepcopy(prepared.receipt)
                if case == "different-generation":
                    receipt["source_compose"]["path"] = str(
                        compose.parent / "another-generation" / compose.name
                    )
                else:
                    receipt["source_compose"]["digest"] = (
                        "sha256:" + "f" * 64
                    )
                self.prepared_releases[inputs.release_root] = SimpleNamespace(
                    **{**prepared.__dict__, "receipt": receipt}
                )
                with mock.patch.object(
                    LAUNCHER.reconciler,
                    "_load_bound_state",
                    return_value=(desired, manifest, compose),
                ), mock.patch.object(
                    LAUNCHER.bootstrap,
                    "_bootstrap_prepublication_locked",
                ) as bootstrap_call, mock.patch.object(
                    LAUNCHER.transaction,
                    "prepare",
                ) as prepare_call:
                    with self.assertRaisesRegex(
                        LAUNCHER.LauncherError,
                        "REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID",
                    ):
                        LAUNCHER.launch(inputs, current_units="absent")
                bootstrap_call.assert_not_called()
                prepare_call.assert_not_called()
                self.assertEqual(list(inputs.unit_directory.iterdir()), [])

    def test_resumer_python_must_equal_the_preparation_tool_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))
            alternate = inputs.python.parent / "alternate-python3"
            alternate.write_bytes(b"#!/bin/sh\nexit 0\n")
            alternate.chmod(0o700)
            changed = replace(inputs, python=alternate)
            with mock.patch.object(
                LAUNCHER.reconciler,
                "_load_bound_state",
                return_value=state,
            ), mock.patch.object(
                LAUNCHER.bootstrap,
                "_bootstrap_prepublication_locked",
            ) as bootstrap_call, mock.patch.object(
                LAUNCHER.transaction,
                "prepare",
            ) as prepare_call:
                with self.assertRaisesRegex(
                    LAUNCHER.LauncherError,
                    "REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID",
                ):
                    LAUNCHER.launch(changed, current_units="absent")
            bootstrap_call.assert_not_called()
            prepare_call.assert_not_called()
            self.assertEqual(list(inputs.unit_directory.iterdir()), [])

    def test_template_mutation_installs_snapshot_then_blocks_prepare(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))
            original = self._target(inputs)
            template = inputs.template_directory / next(
                iter(BOOTSTRAP.TEMPLATE_NAMES.values())
            )
            prepared = self.prepared_releases[inputs.release_root]
            load_count = 0

            def load(_release_root, **_kwargs):
                nonlocal load_count
                load_count += 1
                if load_count == 2:
                    raise LAUNCHER.LauncherError(
                        "REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID"
                    )
                return prepared

            self.release_loader.side_effect = load

            def mutate_and_install(
                _template_directory,
                bindings,
                _old,
                _commands,
                _runner,
                *,
                target_bundle,
                **_kwargs,
            ):
                template.write_bytes(template.read_bytes() + b"\n# mutated\n")
                template.chmod(0o600)
                self.assertEqual(target_bundle, original)
                for artifact in target_bundle.units:
                    installed = inputs.unit_directory / artifact.name
                    installed.write_bytes(artifact.payload)
                    installed.chmod(0o600)
                return LAUNCHER._expected_bootstrap_receipt(
                    target_bundle,
                    bindings,
                )

            with mock.patch.object(
                LAUNCHER.reconciler,
                "_load_bound_state",
                return_value=state,
            ), mock.patch.object(
                LAUNCHER.bootstrap,
                "_bootstrap_prepublication_locked",
                side_effect=mutate_and_install,
            ), mock.patch.object(
                LAUNCHER.transaction,
                "prepare",
            ) as prepare_call:
                with self.assertRaisesRegex(
                    LAUNCHER.LauncherError,
                    "REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID",
                ):
                    LAUNCHER.launch(inputs, current_units="absent")
            prepare_call.assert_not_called()
            for artifact in original.units:
                self.assertEqual(
                    (inputs.unit_directory / artifact.name).read_bytes(),
                    artifact.payload,
                )

    def test_known_old_upgrade_uses_only_managed_prior_sidecars(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            first, state = self._fixture(base, marker="one")
            self._launch(first, state, current_units="absent")
            active = first.state_parent / TRANSACTION.UPGRADES_DIRECTORY / (
                TRANSACTION.ACTIVE_FILE
            )
            active.unlink()
            TRANSACTION.reconciler._fsync_directory(active.parent)
            old_target = self._target(first)
            second, second_state = self._fixture(base, marker="two")
            captured = []

            def upgrading(*args, **kwargs):
                captured.append(args[2])
                return self._bootstrap(second)(*args, **kwargs)

            result, _bootstrap_call, _prepare_call = self._launch(
                second,
                second_state,
                current_units="managed",
                bootstrap_side_effect=upgrading,
                prepare_side_effect=self._prepare(
                    second,
                    operation_id="reviewer-launch-two",
                ),
            )

            self.assertEqual(result["code"], LAUNCHER.LAUNCH_CODE)
            self.assertEqual(captured, [old_target])
            self.assertEqual(
                LAUNCHER._load_current(
                    second.stable_state,
                    second.stable_state / LAUNCHER.SNAPSHOTS_DIRECTORY,
                )[3],
                self._target(second),
            )

    def test_bootstrap_failure_never_prepares_and_each_unit_boundary_resumes(self):
        for boundary in (1, 2, 3):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                inputs, state = self._fixture(Path(temporary))
                with mock.patch.object(
                    LAUNCHER.reconciler,
                    "_load_bound_state",
                    return_value=state,
                ), mock.patch.object(
                    LAUNCHER.bootstrap,
                    "_bootstrap_prepublication_locked",
                    side_effect=self._bootstrap(inputs, fail_after=boundary),
                ), mock.patch.object(LAUNCHER.transaction, "prepare") as prepare:
                    with self.assertRaises(BOOTSTRAP.BootstrapError):
                        LAUNCHER.launch(inputs, current_units="absent")
                prepare.assert_not_called()
                self.assertTrue(
                    (inputs.stable_state / LAUNCHER.PENDING_FILE).is_file()
                )
                result, _bootstrap_call, prepare_call = self._launch(
                    inputs,
                    state,
                    current_units="absent",
                )
                self.assertEqual(result["code"], LAUNCHER.LAUNCH_CODE)
                prepare_call.assert_called_once()

    def test_each_prebootstrap_evidence_file_boundary_resumes(self):
        for boundary in range(1, 10):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                inputs, state = self._fixture(Path(temporary))
                real_publish = LAUNCHER._publish_exact_file
                count = 0

                def crash_after(directory, name, payload):
                    nonlocal count
                    real_publish(directory, name, payload)
                    count += 1
                    if count == boundary:
                        raise InjectedCrash()

                with mock.patch.object(
                    LAUNCHER.reconciler,
                    "_load_bound_state",
                    return_value=state,
                ), mock.patch.object(
                    LAUNCHER,
                    "_publish_exact_file",
                    side_effect=crash_after,
                ), mock.patch.object(
                    LAUNCHER.bootstrap,
                    "_bootstrap_prepublication_locked",
                    side_effect=self._bootstrap(inputs),
                ), mock.patch.object(LAUNCHER.transaction, "prepare") as prepare:
                    with self.assertRaises(InjectedCrash):
                        LAUNCHER.launch(inputs, current_units="absent")
                prepare.assert_not_called()
                mode = (
                    "managed"
                    if (inputs.stable_state / LAUNCHER.CURRENT_FILE).exists()
                    else "absent"
                )
                result, _bootstrap_call, _prepare_call = self._launch(
                    inputs,
                    state,
                    current_units=mode,
                )
                self.assertEqual(result["code"], LAUNCHER.LAUNCH_CODE)

    def test_each_preprepare_evidence_fsync_boundary_resumes(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))
            real_fsync = LAUNCHER.reconciler._fsync_directory
            calls = 0
            before_prepare = 0

            def count_fsync(path):
                nonlocal calls
                real_fsync(path)
                calls += 1

            def record_prepare(*args, **kwargs):
                nonlocal before_prepare
                before_prepare = calls
                return self._prepare(inputs)(*args, **kwargs)

            with mock.patch.object(
                LAUNCHER.reconciler,
                "_fsync_directory",
                side_effect=count_fsync,
            ):
                self._launch(
                    inputs,
                    state,
                    current_units="absent",
                    prepare_side_effect=record_prepare,
                )
            self.assertGreater(before_prepare, 0)

        for boundary in range(1, before_prepare + 1):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                inputs, state = self._fixture(Path(temporary))
                real_fsync = LAUNCHER.reconciler._fsync_directory
                calls = 0

                def crash_after_fsync(path):
                    nonlocal calls
                    real_fsync(path)
                    calls += 1
                    if calls == boundary:
                        raise InjectedCrash()

                with mock.patch.object(
                    LAUNCHER.reconciler,
                    "_fsync_directory",
                    side_effect=crash_after_fsync,
                ), mock.patch.object(
                    LAUNCHER,
                    "_prove_prepared_plan",
                    return_value=PLAN_DIGEST,
                ), mock.patch.object(
                    LAUNCHER.bootstrap,
                    "_bootstrap_prepublication_locked",
                    side_effect=self._bootstrap(inputs),
                ), mock.patch.object(
                    LAUNCHER.transaction,
                    "prepare",
                ) as prepare, mock.patch.object(
                    LAUNCHER.reconciler,
                    "_load_bound_state",
                    return_value=state,
                ):
                    with self.assertRaises(InjectedCrash):
                        LAUNCHER.launch(inputs, current_units="absent")
                prepare.assert_not_called()
                mode = (
                    "managed"
                    if (inputs.stable_state / LAUNCHER.CURRENT_FILE).exists()
                    else "absent"
                )
                result, _bootstrap_call, _prepare_call = self._launch(
                    inputs,
                    state,
                    current_units=mode,
                )
                self.assertEqual(result["code"], LAUNCHER.LAUNCH_CODE)

    def test_exact_file_recovers_hardlink_and_unflushed_unlink_windows(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            directory.chmod(0o700)
            payload = b"sealed\n"
            for name in (LAUNCHER.PENDING_FILE, LAUNCHER.FIRST_INSTALL_FILE):
                with self.subTest(name=name, window="post-link"):
                    final = directory / name
                    staging = directory / f".{name}.next-1-abcdefabcdef"
                    staging.write_bytes(payload)
                    staging.chmod(0o600)
                    os.link(staging, final)
                    LAUNCHER._publish_exact_file(directory, name, payload)
                    self.assertEqual(final.read_bytes(), payload)
                    self.assertEqual(final.lstat().st_nlink, 1)
                    final.unlink()
                with self.subTest(name=name, window="post-unlink"):
                    final = directory / name
                    final.write_bytes(payload)
                    final.chmod(0o600)
                    with mock.patch.object(
                        LAUNCHER.reconciler,
                        "_fsync_directory",
                        wraps=LAUNCHER.reconciler._fsync_directory,
                    ) as fsync:
                        LAUNCHER._publish_exact_file(directory, name, payload)
                    fsync.assert_called()
                    final.unlink()

    def test_partial_staging_is_discarded_for_every_evidence_class(self):
        names = (
            BOOTSTRAP.UNIT_NAMES[0],
            LAUNCHER.SNAPSHOT_FILE,
            LAUNCHER.BOOTSTRAP_RECEIPT_FILE,
            LAUNCHER.CANDIDATE_COMPOSE_FILE,
            LAUNCHER.PENDING_FILE,
            LAUNCHER.FIRST_INSTALL_FILE,
            "reviewer-launch-test.json",
        )
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary).resolve()
                directory.chmod(0o700)
                staging = directory / f".{name}.next-1-abcdefabcdef"
                staging.write_bytes(b"")
                staging.chmod(0o600)

                LAUNCHER._publish_exact_file(directory, name, b"complete\n")

                self.assertEqual((directory / name).read_bytes(), b"complete\n")
                self.assertFalse(staging.exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            old = JOURNAL.canonical_json({"old": True})
            new = JOURNAL.canonical_json({"new": True})
            current = root / LAUNCHER.CURRENT_FILE
            current.write_bytes(old)
            current.chmod(0o600)
            staging = root / ".current.json.next-1-abcdefabcdef"
            staging.write_bytes(b"")
            staging.chmod(0o600)

            LAUNCHER._replace_pointer(root, new, expected=old)

            self.assertEqual(current.read_bytes(), new)
            self.assertFalse(staging.exists())

    def test_prepare_failure_retains_managed_target_but_no_preparation_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))
            failure = TRANSACTION.UpgradeError("REVIEWER_UPGRADE_HEALTH_FAILED")
            with self.assertRaises(TRANSACTION.UpgradeError):
                self._launch(
                    inputs,
                    state,
                    current_units="absent",
                    prepare_side_effect=self._prepare(inputs, fail=failure),
                )
            self.assertIsNotNone(
                LAUNCHER._load_current(
                    inputs.stable_state,
                    inputs.stable_state / LAUNCHER.SNAPSHOTS_DIRECTORY,
                )
            )
            self.assertEqual(
                list(
                    (
                        inputs.stable_state
                        / LAUNCHER.PREPARATIONS_DIRECTORY
                    ).iterdir()
                ),
                [],
            )

    def test_unpublished_transaction_orphan_does_not_pin_retry_identifier(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))

            def create_orphan_then_fail(*_args, **_kwargs):
                upgrades = TRANSACTION._ensure_upgrades_directory(
                    inputs.state_parent
                )
                JOURNAL.create_transaction_directory(
                    upgrades / "reviewer-unpublished-orphan"
                )
                raise TRANSACTION.UpgradeError("REVIEWER_UPGRADE_FAILED")

            with self.assertRaises(TRANSACTION.UpgradeError):
                self._launch(
                    inputs,
                    state,
                    current_units="absent",
                    prepare_side_effect=create_orphan_then_fail,
                )
            self.assertFalse(
                (
                    inputs.state_parent
                    / TRANSACTION.UPGRADES_DIRECTORY
                    / TRANSACTION.ACTIVE_FILE
                ).exists()
            )

            result, _bootstrap_call, prepare_call = self._launch(
                inputs,
                state,
                current_units="absent",
                prepare_side_effect=self._prepare(
                    inputs,
                    operation_id="reviewer-fresh-retry",
                ),
            )

            self.assertEqual(result["operation_id"], "reviewer-fresh-retry")
            prepare_call.assert_called_once()

    def test_active_plan_recovers_missing_preparation_without_rebootstrap(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))
            with mock.patch.object(
                LAUNCHER,
                "_publish_preparation",
                side_effect=InjectedCrash(),
            ):
                with self.assertRaises(InjectedCrash):
                    self._launch(inputs, state, current_units="absent")
            current = LAUNCHER._load_current(
                inputs.stable_state,
                inputs.stable_state / LAUNCHER.SNAPSHOTS_DIRECTORY,
            )
            self.assertIsNotNone(current)

            def load_transaction(_upgrades, active):
                descriptor = os.open(inputs.serial_lock_file, os.O_RDWR)
                try:
                    serial_binding = TRANSACTION.reconciler._validate_lock_descriptor(
                        descriptor,
                        inputs.serial_lock_file,
                    )
                finally:
                    os.close(descriptor)
                plan = {
                    "candidate_compose_digest": current[2]["launch_binding"][
                        "candidate_compose_digest"
                    ],
                    "candidate_repository_root": str(inputs.repository),
                    "candidate_image_ref": current[2]["launch_binding"][
                        "prepared_reviewer_image_ref"
                    ],
                    "candidate_image_id": current[2]["launch_binding"][
                        "prepared_reviewer_image_id"
                    ],
                    "finalize": {
                        "reconcile_bindings": {
                            "admin_secret_file": str(inputs.admin_secret_file),
                            "config_file": str(inputs.config_file),
                            "lock_file": str(inputs.lock_file),
                            "operation_directory": str(
                                inputs.operation_directory
                            ),
                        },
                        "unit_directory": str(inputs.unit_directory),
                    },
                    "operation_id": active["operation_id"],
                    "project": inputs.project,
                    "serial_lock": serial_binding,
                    "source_state_directory": str(inputs.state_directory),
                }
                return (
                    inputs.state_parent / "synthetic-transaction",
                    {"plan_digest": active["plan_digest"]},
                    plan,
                    {"phase": TRANSACTION.QUIESCING},
                )

            with mock.patch.object(
                LAUNCHER.transaction,
                "_load_transaction",
                side_effect=load_transaction,
            ), mock.patch.object(
                LAUNCHER.transaction,
                "_candidate_compose",
            ), mock.patch.object(
                LAUNCHER,
                "_prove_prepared_plan",
                return_value=PLAN_DIGEST,
            ):
                result, bootstrap_call, prepare_call = self._launch(
                    inputs,
                    state,
                    current_units="absent",
                )

            self.assertEqual(result["code"], LAUNCHER.LAUNCH_CODE)
            self.assertEqual(result["operation_id"], "reviewer-launch-test")
            bootstrap_call.assert_not_called()
            prepare_call.assert_not_called()
            self.assertTrue(
                (
                    inputs.stable_state
                    / LAUNCHER.PREPARATIONS_DIRECTORY
                    / "reviewer-launch-test.json"
                ).is_file()
            )

    def test_active_recovery_reproves_retained_release_before_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))
            with mock.patch.object(
                LAUNCHER,
                "_publish_preparation",
                side_effect=InjectedCrash(),
            ):
                with self.assertRaises(InjectedCrash):
                    self._launch(inputs, state, current_units="absent")
            prepared = self.prepared_releases[inputs.release_root]
            self.release_loader.reset_mock()
            self.release_loader.side_effect = [
                prepared,
                LAUNCHER.LauncherError(
                    "REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID"
                ),
            ]
            with self.assertRaisesRegex(
                LAUNCHER.LauncherError,
                "REVIEWER_UPGRADE_LAUNCH_PREPARED_RELEASE_INVALID",
            ):
                self._launch(inputs, state, current_units="absent")
            self.assertEqual(self.release_loader.call_count, 2)
            self.assertTrue(inputs.release_root.is_dir())
            self.assertFalse(
                (
                    inputs.stable_state
                    / LAUNCHER.PREPARATIONS_DIRECTORY
                    / "reviewer-launch-test.json"
                ).exists()
            )

    def test_original_candidate_mutation_at_prepare_gap_uses_sealed_sidecar(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))
            original = inputs.candidate_compose.read_bytes()

            def mutate_then_prepare(*args, **kwargs):
                sealed_candidate = args[1]
                self.assertNotEqual(sealed_candidate, inputs.candidate_compose)
                self.assertEqual(sealed_candidate.read_bytes(), original)
                inputs.candidate_compose.write_bytes(b'{"mutated":true}')
                inputs.candidate_compose.chmod(0o600)
                self.assertEqual(sealed_candidate.read_bytes(), original)
                return self._prepare(inputs)(*args, **kwargs)

            result, _bootstrap_call, prepare_call = self._launch(
                inputs,
                state,
                current_units="absent",
                prepare_side_effect=mutate_then_prepare,
            )

            self.assertEqual(result["code"], LAUNCHER.LAUNCH_CODE)
            prepare_call.assert_called_once()
            passed = prepare_call.call_args.args[1]
            self.assertEqual(passed.read_bytes(), original)
            self.assertEqual(
                LAUNCHER._digest(passed.read_bytes()),
                LAUNCHER._load_current(
                    inputs.stable_state,
                    inputs.stable_state / LAUNCHER.SNAPSHOTS_DIRECTORY,
                )[2]["launch_binding"]["candidate_compose_digest"],
            )

    def test_wrong_bootstrap_receipt_blocks_pointer_and_prepare(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))

            def wrong(*args, **kwargs):
                receipt = self._bootstrap(inputs)(*args, **kwargs)
                receipt = deepcopy(receipt)
                receipt["status"] = "wrong"
                return receipt

            with mock.patch.object(
                LAUNCHER.reconciler,
                "_load_bound_state",
                return_value=state,
            ), mock.patch.object(
                LAUNCHER.bootstrap,
                "_bootstrap_prepublication_locked",
                side_effect=wrong,
            ), mock.patch.object(LAUNCHER.transaction, "prepare") as prepare:
                with self.assertRaisesRegex(
                    LAUNCHER.LauncherError,
                    "REVIEWER_UPGRADE_LAUNCH_BOOTSTRAP_RECEIPT_INVALID",
                ):
                    LAUNCHER.launch(inputs, current_units="absent")
            prepare.assert_not_called()
            self.assertFalse(
                (inputs.stable_state / LAUNCHER.CURRENT_FILE).exists()
            )

    def test_serial_lock_contention_and_active_race_never_prepare(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))
            inputs.serial_lock_file.touch(mode=0o600)
            descriptor = os.open(inputs.serial_lock_file, os.O_RDWR)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                with mock.patch.object(
                    LAUNCHER.reconciler,
                    "_load_bound_state",
                    return_value=state,
                ), mock.patch.object(LAUNCHER.transaction, "prepare") as prepare:
                    with self.assertRaisesRegex(
                        BOOTSTRAP.BootstrapError,
                        "UPGRADE_BOOTSTRAP_CONTENDED",
                    ):
                        LAUNCHER.launch(inputs, current_units="absent")
                prepare.assert_not_called()
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

        with tempfile.TemporaryDirectory() as temporary:
            inputs, state = self._fixture(Path(temporary))

            def create_active(*args, **kwargs):
                receipt = self._bootstrap(inputs)(*args, **kwargs)
                upgrades = TRANSACTION._ensure_upgrades_directory(
                    inputs.state_parent
                )
                TRANSACTION._publish_active(
                    upgrades,
                    "reviewer-raced",
                    PLAN_DIGEST,
                )
                return receipt

            with mock.patch.object(
                LAUNCHER.reconciler,
                "_load_bound_state",
                return_value=state,
            ), mock.patch.object(
                LAUNCHER.bootstrap,
                "_bootstrap_prepublication_locked",
                side_effect=create_active,
            ), mock.patch.object(LAUNCHER.transaction, "prepare") as prepare:
                with self.assertRaisesRegex(
                    BOOTSTRAP.BootstrapError,
                    "UPGRADE_BOOTSTRAP_ACTIVE_PRESENT",
                ):
                    LAUNCHER.launch(inputs, current_units="absent")
            prepare.assert_not_called()

    def test_borrowed_transaction_serial_fd_is_retained_on_success_and_failure(self):
        for outcome in ("success", "failure"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                root.chmod(0o700)
                state = root / "state"
                state.mkdir(mode=0o700)
                serial = root / TRANSACTION.SERIAL_LOCK_FILE
                serial.touch(mode=0o600)
                descriptor = os.open(
                    serial,
                    os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
                )
                side_effect = (
                    None
                    if outcome == "success"
                    else TRANSACTION.UpgradeError("REVIEWER_UPGRADE_INPUT_INVALID")
                )
                with mock.patch.object(
                    TRANSACTION,
                    "_prepare_after_serial_preflight",
                    return_value={"ok": True},
                    side_effect=side_effect,
                ):
                    if side_effect is None:
                        TRANSACTION.prepare(
                            state,
                            root / "candidate",
                            unit_directory=root,
                            lock_file=root / "lock",
                            operation_directory=root,
                            serial_lock_file=serial,
                            serial_lock_descriptor=descriptor,
                        )
                    else:
                        with self.assertRaises(TRANSACTION.UpgradeError):
                            TRANSACTION.prepare(
                                state,
                                root / "candidate",
                                unit_directory=root,
                                lock_file=root / "lock",
                                operation_directory=root,
                                serial_lock_file=serial,
                                serial_lock_descriptor=descriptor,
                            )
                os.fstat(descriptor)
                probe = os.open(serial, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(probe)
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def test_rebound_borrowed_serial_fd_fails_before_prepare_body(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            state = root / "state"
            state.mkdir(mode=0o700)
            serial = root / TRANSACTION.SERIAL_LOCK_FILE
            serial.touch(mode=0o600)
            descriptor = os.open(
                serial,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
            )
            serial.unlink()
            serial.touch(mode=0o600)
            with mock.patch.object(
                TRANSACTION,
                "_prepare_after_serial_preflight",
            ) as body:
                with self.assertRaisesRegex(
                    TRANSACTION.UpgradeError,
                    "REVIEWER_UPGRADE_SERIAL_LOCK_INVALID",
                ):
                    TRANSACTION.prepare(
                        state,
                        root / "candidate",
                        unit_directory=root,
                        lock_file=root / "lock",
                        operation_directory=root,
                        serial_lock_file=serial,
                        serial_lock_descriptor=descriptor,
                    )
            body.assert_not_called()
            os.close(descriptor)

    def test_borrowed_serial_requires_cloexec_and_exact_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            state = root / "state"
            state.mkdir(mode=0o700)
            serial = root / TRANSACTION.SERIAL_LOCK_FILE
            serial.touch(mode=0o600)
            descriptor = os.open(serial, os.O_RDWR)
            fcntl.fcntl(descriptor, fcntl.F_SETFD, 0)
            with mock.patch.object(
                TRANSACTION,
                "_prepare_after_serial_preflight",
            ) as body:
                with self.assertRaisesRegex(
                    TRANSACTION.UpgradeError,
                    "REVIEWER_UPGRADE_SERIAL_LOCK_INVALID",
                ):
                    TRANSACTION.prepare(
                        state,
                        root / "candidate",
                        unit_directory=root,
                        lock_file=root / "lock",
                        operation_directory=root,
                        serial_lock_file=serial,
                        serial_lock_descriptor=descriptor,
                    )
            body.assert_not_called()
            os.close(descriptor)

            descriptor = os.open(
                serial,
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
            )
            with mock.patch.object(
                TRANSACTION,
                "_prepare_after_serial_preflight",
            ) as body:
                with self.assertRaisesRegex(
                    TRANSACTION.UpgradeError,
                    "REVIEWER_UPGRADE_SERIAL_LOCK_INVALID",
                ):
                    TRANSACTION.prepare(
                        state,
                        root / "candidate",
                        unit_directory=root,
                        lock_file=root / "lock",
                        operation_directory=root,
                        serial_lock_file=root / "different.lock",
                        serial_lock_descriptor=descriptor,
                    )
            body.assert_not_called()
            os.close(descriptor)

    def test_cli_abi_canonical_output_and_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs, _state = self._fixture(Path(temporary))
            argv = ["launch"]
            for option, value in (
                ("release-root", inputs.release_root),
                ("repository", inputs.repository),
                ("state-directory", inputs.state_directory),
                ("candidate-compose", inputs.candidate_compose),
                ("unit-directory", inputs.unit_directory),
                ("lock-file", inputs.lock_file),
                ("operation-directory", inputs.operation_directory),
                ("serial-lock-file", inputs.serial_lock_file),
                ("config-file", inputs.config_file),
                ("admin-secret-file", inputs.admin_secret_file),
                ("python", inputs.python),
                ("systemctl", inputs.systemctl),
                ("systemd-analyze", inputs.systemd_analyze),
                ("home", inputs.home),
                ("xdg-runtime-directory", inputs.xdg_runtime_directory),
            ):
                argv.extend((f"--{option}", str(value)))
            argv.extend(("--project", inputs.project, "--current-units", "absent"))
            result = {
                "bootstrap_receipt_digest": "sha256:" + "1" * 64,
                "code": LAUNCHER.LAUNCH_CODE,
                "operation_id": "reviewer-launch-test",
                "phase": "quiescing",
                "preparation_digest": "sha256:" + "2" * 64,
                "snapshot_digest": "sha256:" + "3" * 64,
                "status": "quiescing",
            }
            output = mock.Mock(buffer=io.BytesIO())
            error = mock.Mock(buffer=io.BytesIO())
            with mock.patch.object(
                LAUNCHER,
                "launch",
                return_value=result,
            ) as launch, mock.patch.object(
                LAUNCHER.sys,
                "stdout",
                output,
            ), mock.patch.object(LAUNCHER.sys, "stderr", error):
                status = LAUNCHER.main(argv)
            self.assertEqual(status, 0)
            self.assertEqual(
                output.buffer.getvalue(),
                JOURNAL.canonical_json(result) + b"\n",
            )
            self.assertEqual(error.buffer.getvalue(), b"")
            self.assertIsNone(
                launch.call_args.args[0].__dict__.get("serial_lock_descriptor")
            )

            output = mock.Mock(buffer=io.BytesIO())
            error = mock.Mock(buffer=io.BytesIO())
            with mock.patch.object(
                LAUNCHER,
                "launch",
                side_effect=LAUNCHER.LauncherError(
                    "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID"
                ),
            ), mock.patch.object(
                LAUNCHER.sys,
                "stdout",
                output,
            ), mock.patch.object(LAUNCHER.sys, "stderr", error):
                status = LAUNCHER.main(argv)
            self.assertEqual(status, 78)
            self.assertEqual(output.buffer.getvalue(), b"")
            self.assertEqual(
                error.buffer.getvalue(),
                JOURNAL.canonical_json(
                    {
                        "code": "REVIEWER_UPGRADE_LAUNCH_EVIDENCE_INVALID",
                        "status": "failed",
                    }
                )
                + b"\n",
            )

            output = mock.Mock(buffer=io.BytesIO())
            error = mock.Mock(buffer=io.BytesIO())
            with mock.patch.object(
                LAUNCHER.sys,
                "stdout",
                output,
            ), mock.patch.object(LAUNCHER.sys, "stderr", error):
                status = LAUNCHER.main(["launch"])
            self.assertEqual(status, 78)

    def test_bounded_command_runner_has_fixed_environment_and_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home = root / "home"
            runtime = root / "runtime"
            home.mkdir()
            runtime.mkdir()
            runner = LAUNCHER.BoundedCommandRunner(
                home=home,
                xdg_runtime_directory=runtime,
            )
            completed = subprocess.CompletedProcess(
                ["/usr/bin/systemctl"],
                0,
                stdout=b"ready\n",
                stderr=b"",
            )
            with mock.patch.object(
                LAUNCHER.subprocess,
                "run",
                return_value=completed,
            ) as invoked:
                payload = runner(["/usr/bin/systemctl", "--user"], timeout=3)
            self.assertEqual(payload, b"ready\n")
            kwargs = invoked.call_args.kwargs
            self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 3.0)
            self.assertEqual(kwargs["env"]["HOME"], str(home))
            self.assertEqual(
                kwargs["env"]["XDG_RUNTIME_DIR"],
                str(runtime),
            )
            self.assertNotIn("DOCKER_HOST", kwargs["env"])

            for completed_or_error in (
                subprocess.CompletedProcess(
                    ["/usr/bin/systemctl"],
                    1,
                    stdout=b"",
                    stderr=b"failed",
                ),
                subprocess.CompletedProcess(
                    ["/usr/bin/systemctl"],
                    0,
                    stdout=b"x" * (LAUNCHER.MAX_COMMAND_BYTES + 1),
                    stderr=b"",
                ),
                subprocess.TimeoutExpired(["systemctl"], 3),
            ):
                with self.subTest(result=type(completed_or_error).__name__), mock.patch.object(
                    LAUNCHER.subprocess,
                    "run",
                    side_effect=(
                        completed_or_error
                        if isinstance(completed_or_error, Exception)
                        else None
                    ),
                    return_value=(
                        completed_or_error
                        if not isinstance(completed_or_error, Exception)
                        else None
                    ),
                ):
                    with self.assertRaisesRegex(
                        LAUNCHER.LauncherError,
                        "REVIEWER_UPGRADE_LAUNCH_COMMAND_FAILED",
                    ):
                        runner(["/usr/bin/systemctl"], timeout=3)


if __name__ == "__main__":
    unittest.main()
