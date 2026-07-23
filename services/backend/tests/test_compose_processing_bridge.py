# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
from array import array
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "services" / "backend" / "src"
sys.path.insert(0, str(SOURCE))

from tacua_backend import processing_bridge as CLIENT  # noqa: E402


SCRIPT_PATH = (
    ROOT
    / "services"
    / "backend"
    / "scripts"
    / "run_compose_isolated_processing.py"
)
SHORT_TEMP_ROOT = Path("/tmp").resolve()


def _load_script():
    specification = importlib.util.spec_from_file_location(
        "tacua_compose_processing_bridge_test",
        SCRIPT_PATH,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("Compose processing bridge cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


BRIDGE = _load_script()


class ComposeProcessingBridgeTests(unittest.TestCase):
    def _write_create_receipt(
        self,
        operation: Path,
        *,
        name: str,
        outcome: str,
        project: str = "t",
        purpose: str = "worker",
        role: str | None = None,
        container_id: str | None = None,
    ) -> dict[str, object]:
        selected_role = role or BRIDGE.BRIDGE_WORKER_ROLE
        BRIDGE._write_create_receipt(
            operation,
            {
                "container_id": container_id,
                "contract_version": BRIDGE.CREATE_RECEIPT_CONTRACT,
                "name": name,
                "outcome": outcome,
                "project": project,
                "purpose": purpose,
                "role": selected_role,
            },
        )
        receipt = BRIDGE._load_create_receipt(
            operation,
            required=True,
        )
        assert receipt is not None
        return receipt

    def _journal_document(
        self,
        *,
        backend_id: str,
        compose_payload: bytes,
        config: Path,
        image_id: str,
        project: str,
        secret: Path,
        worker_id: str | None = None,
        worker_name: str | None = None,
    ) -> dict[str, object]:
        return {
            "adapter_contract": "tacua.local-processing-command@1.0.0",
            "backend_container_id": backend_id,
            "baseline_state_verified": True,
            "compose_digest": (
                "sha256:"
                + hashlib.sha256(compose_payload).hexdigest()
            ),
            "config_identity": BRIDGE._regular_mount_identity(
                config,
                "public config",
            ),
            "configured_image": "tacua-backend:test",
            "contract_version": BRIDGE.OPERATION_CONTRACT,
            "host_bundle_digest": "sha256:" + "d" * 64,
            "image_id": image_id,
            "isolated_command_digest": "sha256:" + "f" * 64,
            "max_stages": 1,
            "original_repository_root": str(ROOT),
            "phase": "worker_starting" if worker_id else "baseline_verified",
            "project": project,
            "run_once": True,
            "secret_identity": BRIDGE._regular_mount_identity(
                secret,
                "administrator secret",
            ),
            "state_verified_after_worker": False,
            "state_volume": "tacua-test_tacua-state",
            "verifier_container_id": None,
            "verifier_name": None,
            "worker_container_id": worker_id,
            "worker_id": "worker_test",
            "worker_name": worker_name,
            "worker_started": worker_id is not None,
        }

    def _exercise_lifecycle(
        self,
        *,
        worker_failure: BRIDGE.ComposeProcessingError | None,
        recovery_backend_status: str = "exited",
        release_effect: object = None,
        verify_effect: object = None,
        wait_effect: object = None,
        preflight_failure: Exception | None = None,
    ) -> tuple[
        dict[str, object] | None,
        list[list[str]],
        mock.Mock,
        mock.Mock,
        mock.Mock,
        BRIDGE.ComposeProcessingError | None,
    ]:
        backend_id = "a" * 64
        worker_id = "b" * 64
        image_id = "sha256:" + "c" * 64
        state_volume = "tacua-test_tacua-state"
        configured_image = "tacua-backend:test"
        docker_calls: list[list[str]] = []

        def fake_docker(argv, **_kwargs):
            arguments = list(argv)
            docker_calls.append(arguments)
            stdout = b""
            returncode = 0
            if "ps" in arguments and "backend" in arguments:
                stdout = (backend_id + "\n").encode("ascii")
            elif arguments[:2] == ["container", "create"]:
                stdout = (worker_id + "\n").encode("ascii")
            elif arguments[:2] == ["container", "inspect"]:
                returncode = 1
            return subprocess.CompletedProcess(
                ["docker", *arguments],
                returncode,
                stdout,
                b"",
            )

        worker_summary = {
            "claim_retries": 0,
            "last_job_id": "job_synthetic",
            "mode": "run_once",
            "processed_stages": 1,
            "queue_empty": False,
            "stage_limit_reached": True,
        }
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            root = Path(temporary)
            compose_file = root / "compose.json"
            config_file = root / "config.json"
            secret_file = root / "admin-secret"
            isolated_file = root / "isolated-command.json"
            compose_file.write_bytes(b'{"name":"tacua-test"}')
            config_file.write_text("{}", encoding="utf-8")
            secret_file.write_bytes(b"synthetic")
            isolated_file.write_text("{}", encoding="utf-8")
            args = argparse.Namespace(
                adapter_contract="tacua.local-processing-command@1.0.0",
                admin_secret_file=secret_file,
                allow_mutable_image=True,
                compose_json=compose_file,
                config_file=config_file,
                drain=False,
                expected_published_port=18080,
                isolated_command_file=isolated_file,
                max_stages=1,
                operation_directory=root.resolve(),
                project="tacua-test",
                run_once=True,
                worker_id="worker_test",
            )
            verify_state = mock.Mock(side_effect=verify_effect)
            smoke = mock.Mock()
            wait_healthy = mock.Mock(side_effect=wait_effect)
            worker_effect: object = worker_summary
            if worker_failure is not None:
                worker_effect = worker_failure
            create_sequence = 0

            def preflight(*_args, **kwargs):
                self.assertEqual(
                    kwargs["expected_published_port"],
                    18080,
                )
                if preflight_failure is not None:
                    raise preflight_failure
                return {"compose": {"published_port": "18080"}}

            def prepare_create(**kwargs):
                nonlocal create_sequence
                create_sequence += 1
                docker_calls.append(["container", "create"])
                return {
                    "gate_descriptor": 100 + create_sequence,
                    "name": kwargs["name"],
                    "pid": 200 + create_sequence,
                    "project": kwargs["project"],
                    "purpose": kwargs["purpose"],
                    "role": kwargs["role"],
                }

            def finish_create(_operation, attempt, *, start):
                return {
                    "container_id": (
                        worker_id
                        if start
                        and attempt["role"] == BRIDGE.BRIDGE_WORKER_ROLE
                        else None
                    ),
                    "contract_version": BRIDGE.CREATE_RECEIPT_CONTRACT,
                    "name": attempt["name"],
                    "outcome": "created" if start else "not_started",
                    "project": attempt["project"],
                    "purpose": attempt["purpose"],
                    "role": attempt["role"],
                }

            def broker_process(
                _socket_path,
                command_snapshot,
                _command_digest,
                _max_requests,
            ):
                self.assertEqual(
                    stat.S_IMODE(command_snapshot.stat().st_mode),
                    0o600,
                )
                return object()

            consumers = [
                {backend_id},
                {backend_id},
                {backend_id, worker_id},
                {backend_id},
                {backend_id},
            ]
            with (
                mock.patch.multiple(
                    BRIDGE,
                    _acquire_host_lock=mock.Mock(return_value=99),
                    _inspect_worker=mock.Mock(),
                    _preflight_state_verifier_capacity=mock.Mock(),
                    _prepare_broker_descriptor_limit=mock.Mock(),
                    _prepare_container_create=mock.Mock(
                        side_effect=prepare_create
                    ),
                    _release_host_lock=mock.Mock(
                        side_effect=release_effect
                    ),
                    _stop_broker=mock.Mock(),
                    _verify_host_bundle_matches_image=mock.Mock(
                        return_value="sha256:" + "d" * 64
                    ),
                    _wait_backend_healthy=wait_healthy,
                    deployment_preflight=mock.Mock(
                        side_effect=preflight
                    ),
                ),
                mock.patch.object(
                    BRIDGE,
                    "_finish_container_create",
                    side_effect=finish_create,
                ),
                mock.patch.object(BRIDGE, "_clear_create_receipt"),
                mock.patch.object(BRIDGE, "_docker", side_effect=fake_docker),
                mock.patch.object(
                    BRIDGE,
                    "_resolve_deployment",
                    return_value=(state_volume, configured_image),
                ),
                mock.patch.multiple(
                    BRIDGE.RUNNER,
                    load_command=mock.Mock(
                        return_value={"synthetic": True}
                    ),
                    validate_runtime_environment=mock.Mock(),
                ),
                mock.patch.object(
                    BRIDGE,
                    "_inspect_backend",
                    return_value=image_id,
                ),
                mock.patch.object(
                    BRIDGE,
                    "_volume_consumers",
                    side_effect=consumers,
                ),
                mock.patch.object(
                    BRIDGE,
                    "_verify_state_offline",
                    verify_state,
                ),
                mock.patch.object(
                    BRIDGE,
                    "_broker_process",
                    side_effect=broker_process,
                ),
                mock.patch.object(
                    BRIDGE,
                    "_worker_create_argv",
                    return_value=["container", "create"],
                ),
                mock.patch.object(
                    BRIDGE,
                    "_run_created_worker",
                    side_effect=(
                        worker_effect
                        if isinstance(worker_effect, BaseException)
                        else None
                    ),
                    return_value=(
                        worker_effect
                        if not isinstance(worker_effect, BaseException)
                        else None
                    ),
                ),
                mock.patch.object(
                    BRIDGE,
                    "_inspect_container",
                    return_value={
                        "State": {"Status": recovery_backend_status}
                    },
                ),
                mock.patch.object(BRIDGE, "smoke_deployment", smoke),
            ):
                raised = None
                try:
                    result = BRIDGE.run_compose_processing(args)
                except BRIDGE.ComposeProcessingError as error:
                    raised = error
                    result = None
            return (
                result,
                docker_calls,
                verify_state,
                smoke,
                wait_healthy,
                raised,
            )

    def test_adapter_descriptor_targets_preserve_capability_offsets(self) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            root = Path(temporary)
            evidence_path = root / "evidence.bin"
            evidence_path.write_bytes(b"synthetic bridge evidence")
            evidence_descriptor = os.open(evidence_path, os.O_RDONLY)
            try:
                document = {
                    "capture": {
                        "diagnostics": [],
                        "segments": [
                            {
                                "content_digest": "sha256:" + "a" * 64,
                                "read_only_path": f"/dev/fd/{evidence_descriptor}",
                            }
                        ],
                    },
                    "contract_version": "tacua.local-processing-input@1.0.0",
                    "input_digest": "sha256:" + "b" * 64,
                }
                input_path = root / "input.json"
                input_path.write_bytes(CLIENT.canonical_json(document))
                input_descriptor = os.open(input_path, os.O_RDONLY)
                try:
                    targets = CLIENT.adapter_descriptor_targets(
                        Path(f"/dev/fd/{input_descriptor}")
                    )
                    self.assertEqual(
                        targets,
                        (input_descriptor, evidence_descriptor),
                    )
                    self.assertEqual(os.lseek(input_descriptor, 0, os.SEEK_CUR), 0)
                    self.assertEqual(
                        os.lseek(evidence_descriptor, 0, os.SEEK_CUR),
                        0,
                    )
                finally:
                    os.close(input_descriptor)
            finally:
                os.close(evidence_descriptor)

    def test_descriptor_batches_transfer_exact_regular_files(self) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            paths = []
            descriptors = []
            for index in range(CLIENT.FD_BATCH_SIZE + 1):
                path = Path(temporary) / f"evidence-{index}.bin"
                path.write_bytes(str(index).encode("ascii"))
                paths.append(path)
                descriptors.append(os.open(path, os.O_RDONLY))
            left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            received: tuple[int, ...] = ()
            try:
                CLIENT.send_descriptor_batches(left, descriptors)
                received = CLIENT.receive_descriptor_batches(
                    right,
                    len(descriptors),
                )
                self.assertEqual(len(received), len(descriptors))
                for source, copied in zip(descriptors, received, strict=True):
                    self.assertEqual(
                        (os.fstat(source).st_dev, os.fstat(source).st_ino),
                        (os.fstat(copied).st_dev, os.fstat(copied).st_ino),
                    )
            finally:
                left.close()
                right.close()
                for descriptor in descriptors:
                    os.close(descriptor)
                for descriptor in received:
                    os.close(descriptor)

    def test_descriptor_batch_rejections_close_every_received_right(self) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            source_path = Path(temporary) / "source"
            source_path.write_bytes(b"synthetic")
            source = os.open(source_path, os.O_RDONLY)
            try:
                for message, flags, ancillary_prefix in (
                    (b"X", 0, []),
                    (
                        b"F",
                        getattr(socket, "MSG_CTRUNC", 0),
                        [],
                    ),
                    (
                        b"F",
                        0,
                        [(socket.SOL_SOCKET, -1, b"invalid")],
                    ),
                ):
                    received_right = os.dup(source)
                    rights = array("i", [received_right]).tobytes()
                    stream = mock.Mock()
                    stream.recvmsg.return_value = (
                        message,
                        [
                            *ancillary_prefix,
                            (socket.SOL_SOCKET, socket.SCM_RIGHTS, rights),
                        ],
                        flags,
                        None,
                    )
                    with self.assertRaisesRegex(
                        CLIENT.ProcessingBridgeError,
                        "truncated or invalid",
                    ):
                        CLIENT.receive_descriptor_batches(stream, 1)
                    with self.assertRaises(OSError):
                        os.fstat(received_right)

                first = os.dup(source)
                second = os.dup(source)
                rights = array("i", [first, second]).tobytes()
                stream = mock.Mock()
                stream.recvmsg.return_value = (
                    b"F",
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                    0,
                    None,
                )
                with self.assertRaisesRegex(
                    CLIENT.ProcessingBridgeError,
                    "truncated or invalid",
                ):
                    CLIENT.receive_descriptor_batches(stream, 1)
                for descriptor in (first, second):
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
            finally:
                os.close(source)

    def test_broker_descriptor_preflight_handles_infinite_and_low_limits(
        self,
    ) -> None:
        with (
            mock.patch.object(
                BRIDGE.resource,
                "getrlimit",
                return_value=(1024, BRIDGE.resource.RLIM_INFINITY),
            ),
            mock.patch.object(BRIDGE.resource, "setrlimit") as set_limit,
        ):
            BRIDGE._prepare_broker_descriptor_limit()
        set_limit.assert_called_once_with(
            BRIDGE.resource.RLIMIT_NOFILE,
            (
                BRIDGE.BROKER_NOFILE_LIMIT,
                BRIDGE.resource.RLIM_INFINITY,
            )
        )
        with (
            mock.patch.object(
                BRIDGE.resource,
                "getrlimit",
                return_value=(1024, 2048),
            ),
            self.assertRaisesRegex(
                BRIDGE.ComposeProcessingError,
                "descriptor limit",
            ),
        ):
            BRIDGE._prepare_broker_descriptor_limit()

    def test_broker_startup_diagnostic_accepts_only_one_stable_code(
        self,
    ) -> None:
        self.assertEqual(
            BRIDGE._broker_failure_code(b"BRIDGE_PROVENANCE_MISMATCH\n"),
            "BRIDGE_PROVENANCE_MISMATCH",
        )
        for payload in (
            b"",
            b"BRIDGE_FAILURE\nsecret",
            b"bridge_failure\n",
            b"BRIDGE_" + b"A" * 121 + b"\n",
        ):
            self.assertEqual(
                BRIDGE._broker_failure_code(payload),
                "BRIDGE_BROKER_FAILED",
            )

    def test_broker_socket_readiness_waits_for_permission_transition(
        self,
    ) -> None:
        def metadata(file_type: int, mode: int, owner: int) -> os.stat_result:
            return os.stat_result(
                (file_type | mode, 0, 0, 0, owner, 0, 0, 0, 0, 0)
            )

        with mock.patch.object(BRIDGE.os, "geteuid", return_value=1000):
            self.assertEqual(
                BRIDGE._broker_socket_readiness(
                    metadata(stat.S_IFSOCK, 0o700, 1000)
                ),
                "pending",
            )
            self.assertEqual(
                BRIDGE._broker_socket_readiness(
                    metadata(stat.S_IFSOCK, 0o666, 1000)
                ),
                "ready",
            )
            for value in (
                metadata(stat.S_IFSOCK, 0o600, 1000),
                metadata(stat.S_IFSOCK, 0o666, 1001),
                metadata(stat.S_IFREG, 0o666, 1000),
            ):
                self.assertEqual(
                    BRIDGE._broker_socket_readiness(value),
                    "unsafe",
                )

    def test_broker_socket_wait_tolerates_bind_permission_transition(
        self,
    ) -> None:
        pending = os.stat_result(
            (stat.S_IFSOCK | 0o700, 0, 0, 0, 1000, 0, 0, 0, 0, 0)
        )
        ready = os.stat_result(
            (stat.S_IFSOCK | 0o666, 0, 0, 0, 1000, 0, 0, 0, 0, 0)
        )
        process = mock.Mock()
        process.poll.return_value = None
        socket_path = mock.Mock()
        socket_path.lstat.side_effect = (pending, ready)
        with (
            mock.patch.object(BRIDGE.os, "geteuid", return_value=1000),
            mock.patch.object(BRIDGE.time, "sleep") as sleep,
        ):
            self.assertTrue(
                BRIDGE._wait_for_broker_socket(process, socket_path)
            )
        self.assertEqual(socket_path.lstat.call_count, 2)
        sleep.assert_called_once_with(0.02)

    def test_broker_process_returns_after_socket_becomes_ready(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            operation = Path(temporary).resolve()
            socket_path = operation / "processing-bridge.sock"
            script = (
                operation
                / BRIDGE._SOURCE_DIRECTORY_NAME
                / BRIDGE._SOURCE_EXACT_PATHS[0]
            )
            process = mock.Mock()
            stop = mock.Mock()
            with (
                mock.patch.object(
                    BRIDGE,
                    "_VERIFIED_SOURCE_CONTEXT",
                    {
                        "manifest": {"source_digest": "sha256:" + "a" * 64},
                        "operation": operation,
                    },
                ),
                mock.patch.object(BRIDGE, "__file__", str(script)),
                mock.patch.object(
                    BRIDGE,
                    "_bootstrap_exec_environment",
                    return_value={},
                ),
                mock.patch.object(
                    BRIDGE.subprocess,
                    "Popen",
                    return_value=process,
                ),
                mock.patch.object(
                    BRIDGE,
                    "_wait_for_broker_socket",
                    return_value=True,
                ),
                mock.patch.object(BRIDGE, "_stop_broker", stop),
            ):
                self.assertIs(
                    BRIDGE._broker_process(
                        socket_path,
                        operation / "isolated-command.json",
                        "sha256:" + "b" * 64,
                        1,
                    ),
                    process,
                )
            stop.assert_not_called()

    def test_broker_publishes_ready_mode_after_listener_setup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            operation = Path(temporary).resolve()
            socket_path = operation / "processing-bridge.sock"
            digest = "sha256:" + "a" * 64
            events: list[str] = []
            listener = mock.Mock()
            listener.bind.side_effect = lambda _path: events.append("bind")
            listener.listen.side_effect = lambda _count: events.append(
                "listen"
            )
            listener.settimeout.side_effect = lambda _timeout: events.append(
                "timeout"
            )

            def move(value):
                self.assertIs(value, listener)
                events.append("move")
                return listener

            def chmod(_path, mode):
                self.assertEqual(mode, 0o666)
                events.append("chmod")

            with (
                mock.patch.object(
                    BRIDGE,
                    "_VERIFIED_SOURCE_CONTEXT",
                    {
                        "mode": "broker",
                        "operation": operation,
                        "original_root": ROOT,
                        "source_digest": digest,
                    },
                ),
                mock.patch.object(
                    BRIDGE,
                    "_BROKER_FAILURE_STAGE",
                    "ENTRY",
                ),
                mock.patch.object(
                    BRIDGE,
                    "_load_operation_journal",
                    return_value={
                        "host_bundle_digest": digest,
                        "original_repository_root": str(ROOT),
                    },
                ),
                mock.patch.object(
                    BRIDGE,
                    "_prepare_broker_descriptor_limit",
                ),
                mock.patch.object(BRIDGE, "_require_snapshot_digest"),
                mock.patch.object(
                    BRIDGE.RUNNER,
                    "load_command",
                    return_value={"synthetic": True},
                ),
                mock.patch.object(
                    BRIDGE.threading,
                    "Thread",
                    return_value=mock.Mock(),
                ),
                mock.patch.object(
                    BRIDGE.socket,
                    "socket",
                    return_value=listener,
                ),
                mock.patch.object(BRIDGE, "_move_socket_high", side_effect=move),
                mock.patch.object(BRIDGE.os, "umask"),
                mock.patch.object(BRIDGE.os, "getppid", return_value=999),
                mock.patch.object(
                    type(socket_path),
                    "chmod",
                    autospec=True,
                    side_effect=chmod,
                ),
            ):
                self.assertEqual(
                    BRIDGE.run_broker(
                        socket_path,
                        operation / "isolated-command.json",
                        digest,
                        1,
                        123,
                    ),
                    0,
                )
            self.assertEqual(
                events,
                ["bind", "listen", "move", "timeout", "chmod"],
            )

    def test_broker_unexpected_failure_reports_only_stable_stage(
        self,
    ) -> None:
        arguments = argparse.Namespace(
            isolated_command_digest="sha256:" + "a" * 64,
            isolated_command_file=Path("/synthetic/command.json"),
            max_requests=1,
            parent_pid=123,
            socket=Path("/synthetic/bridge.sock"),
        )
        output = mock.Mock()
        parser = mock.Mock()
        parser.parse_args.return_value = arguments
        with (
            mock.patch.object(
                BRIDGE,
                "_BROKER_FAILURE_STAGE",
                "SOCKET_BIND",
            ),
            mock.patch.object(BRIDGE, "_broker_parser", return_value=parser),
            mock.patch.object(BRIDGE.os, "umask"),
            mock.patch.object(
                BRIDGE,
                "run_broker",
                side_effect=RuntimeError("synthetic secret detail"),
            ),
            mock.patch("builtins.print", output),
        ):
            self.assertEqual(BRIDGE.main(["_broker"]), 1)
        output.assert_called_once_with(
            "BRIDGE_BROKER_SOCKET_BIND_FAILED",
            file=BRIDGE.sys.stderr,
        )

    def test_response_header_bound_carries_maximum_preview_manifest(
        self,
    ) -> None:
        files = []
        for index in range(CLIENT.MAX_PREVIEW_FILES):
            prefix = f"preview-{index:04d}-"
            files.append(
                {
                    "content_digest": "sha256:" + "a" * 64,
                    "name": prefix + "x" * (128 - len(prefix)),
                    "size_bytes": CLIENT.MAX_PREVIEW_BYTES,
                }
            )
        encoded = CLIENT.canonical_json(
            {
                "contract_version": CLIENT.RESPONSE_CONTRACT,
                "files": files,
                "result_digest": "sha256:" + "b" * 64,
                "result_size": CLIENT.MAX_RESULT_BYTES,
                "status": "ok",
            }
        )
        self.assertLessEqual(len(encoded), CLIENT.MAX_HEADER_BYTES)

    def test_worker_cleanup_uses_a_successful_exact_absence_query(
        self,
    ) -> None:
        container_id = "a" * 64

        def docker_with_listing(listing: bytes):
            def run(argv, **_kwargs):
                arguments = list(argv)
                return subprocess.CompletedProcess(
                    ["docker", *arguments],
                    1 if arguments[:2] == ["container", "rm"] else 0,
                    (
                        listing
                        if arguments[:2] == ["container", "ls"]
                        else b""
                    ),
                    b"",
                )

            return run

        with mock.patch.object(
            BRIDGE,
            "_docker",
            side_effect=docker_with_listing(b""),
        ):
            BRIDGE._remove_worker(container_id)
        with (
            mock.patch.object(
                BRIDGE,
                "_docker",
                side_effect=docker_with_listing(
                    (container_id + "\n").encode("ascii")
                ),
            ),
            self.assertRaisesRegex(
                BRIDGE.ComposeProcessingError,
                "remained after processing",
            ),
        ):
            BRIDGE._remove_worker(container_id)

    def test_state_verifier_capacity_is_checked_before_downtime(
        self,
    ) -> None:
        container_id = "a" * 64
        success = subprocess.CompletedProcess(
            ["docker"],
            0,
            BRIDGE.canonical_json(
                {
                    "maximum_bytes": (
                        BRIDGE.MAX_COMPOSE_STATE_DATABASE_COPY_BYTES
                    ),
                    "status": "ok",
                }
            )
            + b"\n",
            b"",
        )
        with mock.patch.object(
            BRIDGE,
            "_docker",
            return_value=success,
        ) as docker:
            BRIDGE._preflight_state_verifier_capacity(container_id)
        self.assertEqual(
            docker.call_args.args[0],
            [
                "container",
                "exec",
                container_id,
                "/usr/local/bin/python",
                "-B",
                "-m",
                "tacua_backend.operator_tool",
                "check-compose-state-copy-bound",
                "--state-directory",
                BRIDGE.STATE_IN_CONTAINER,
            ],
        )
        for result in (
            subprocess.CompletedProcess(["docker"], 1, b"", b"failed"),
            subprocess.CompletedProcess(["docker"], 0, b"{}\n", b""),
        ):
            with (
                self.subTest(result=result),
                mock.patch.object(BRIDGE, "_docker", return_value=result),
                self.assertRaises(
                    BRIDGE.ComposeProcessingError
                ) as raised,
            ):
                BRIDGE._preflight_state_verifier_capacity(container_id)
            self.assertEqual(
                raised.exception.code,
                "BRIDGE_STATE_CAPACITY_EXCEEDED",
            )

    def test_container_create_coordinator_gates_and_seals_outcomes(
        self,
    ) -> None:
        container_id = "a" * 64
        cases = (
            ("created", True, 0, container_id),
            ("indeterminate", True, 1, None),
            ("not_started", False, 0, None),
        )
        for outcome, start, returncode, expected_id in cases:
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory(
                dir=SHORT_TEMP_ROOT
            ) as temporary:
                root = Path(temporary).resolve()
                operation = BRIDGE._create_operation_directory(root, "t")
                marker = root / "docker-called"
                name = "tacua-processing-123-" + "b" * 12

                def fake_docker(argv, **_kwargs):
                    marker.write_text(
                        "\n".join(argv),
                        encoding="utf-8",
                    )
                    return subprocess.CompletedProcess(
                        ["docker", *argv],
                        returncode,
                        (
                            (container_id + "\n").encode("ascii")
                            if returncode == 0
                            else b""
                        ),
                        b"",
                    )

                with mock.patch.object(
                    BRIDGE,
                    "_docker",
                    side_effect=fake_docker,
                ):
                    before = BRIDGE.signal.pthread_sigmask(
                        BRIDGE.signal.SIG_BLOCK,
                        set(),
                    )
                    attempt = BRIDGE._prepare_container_create(
                        operation=operation,
                        argv=["container", "create", "--name", name],
                        project="t",
                        role=BRIDGE.BRIDGE_WORKER_ROLE,
                        purpose="worker",
                        name=name,
                    )
                    self.assertFalse(marker.exists())
                    during = BRIDGE.signal.pthread_sigmask(
                        BRIDGE.signal.SIG_BLOCK,
                        set(),
                    )
                    self.assertTrue(
                        {
                            BRIDGE.signal.SIGHUP,
                            BRIDGE.signal.SIGINT,
                            BRIDGE.signal.SIGTERM,
                        }.issubset(during)
                    )
                    receipt = BRIDGE._finish_container_create(
                        operation,
                        attempt,
                        start=start,
                    )
                    after = BRIDGE.signal.pthread_sigmask(
                        BRIDGE.signal.SIG_BLOCK,
                        set(),
                    )
                self.assertEqual(receipt["outcome"], outcome)
                self.assertEqual(after, before)
                self.assertEqual(receipt["container_id"], expected_id)
                self.assertEqual(receipt["name"], name)
                self.assertEqual(receipt["project"], "t")
                self.assertEqual(receipt["purpose"], "worker")
                self.assertEqual(
                    receipt["role"],
                    BRIDGE.BRIDGE_WORKER_ROLE,
                )
                self.assertEqual(marker.exists(), start)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(int(attempt["pid"]), os.WNOHANG)

    def test_container_create_fork_failure_restores_mask_and_closes_pipe(
        self,
    ) -> None:
        read_descriptor, write_descriptor = os.pipe()
        before = BRIDGE.signal.pthread_sigmask(
            BRIDGE.signal.SIG_BLOCK,
            set(),
        )
        try:
            with (
                tempfile.TemporaryDirectory(
                    dir=SHORT_TEMP_ROOT
                ) as temporary,
                mock.patch.object(
                    BRIDGE.os,
                    "pipe",
                    return_value=(read_descriptor, write_descriptor),
                ),
                mock.patch.object(
                    BRIDGE.os,
                    "fork",
                    side_effect=OSError("synthetic fork failure"),
                ),
                self.assertRaisesRegex(OSError, "synthetic fork failure"),
            ):
                BRIDGE._prepare_container_create(
                    operation=Path(temporary),
                    argv=["container", "create"],
                    project="t",
                    role=BRIDGE.BRIDGE_WORKER_ROLE,
                    purpose="worker",
                    name="tacua-processing-123-" + "b" * 12,
                )
            after = BRIDGE.signal.pthread_sigmask(
                BRIDGE.signal.SIG_BLOCK,
                set(),
            )
            self.assertEqual(after, before)
            for descriptor in (read_descriptor, write_descriptor):
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        finally:
            BRIDGE.signal.pthread_sigmask(
                BRIDGE.signal.SIG_SETMASK,
                before,
            )
            for descriptor in (read_descriptor, write_descriptor):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_container_create_receipt_rejects_torn_and_cross_role_data(
        self,
    ) -> None:
        name = "tacua-processing-123-" + "b" * 12
        with tempfile.TemporaryDirectory(
            dir=SHORT_TEMP_ROOT
        ) as temporary:
            operation = Path(temporary)
            receipt_path = operation / BRIDGE.CREATE_RECEIPT_NAME
            receipt_path.write_bytes(b"{malformed")
            receipt_path.chmod(0o600)
            with self.assertRaises(
                BRIDGE.ComposeProcessingError
            ) as malformed:
                BRIDGE._load_create_receipt(operation, required=True)
            self.assertEqual(
                malformed.exception.code,
                "BRIDGE_RECOVERY_UNSAFE",
            )
            receipt_path.unlink()

            BRIDGE._write_create_receipt(
                operation,
                {
                    "container_id": None,
                    "contract_version": BRIDGE.CREATE_RECEIPT_CONTRACT,
                    "name": name,
                    "outcome": "not_started",
                    "project": "t",
                    "purpose": "baseline",
                    "role": BRIDGE.BRIDGE_WORKER_ROLE,
                },
            )
            with self.assertRaises(
                BRIDGE.ComposeProcessingError
            ) as cross_role:
                BRIDGE._load_create_receipt(operation, required=True)
            self.assertEqual(
                cross_role.exception.code,
                "BRIDGE_RECOVERY_UNSAFE",
            )

            receipt_path.unlink()
            next_path = operation / BRIDGE.CREATE_RECEIPT_NEXT_NAME
            next_path.write_bytes(b"synthetic")
            next_path.chmod(0o600)
            with self.assertRaises(
                BRIDGE.ComposeProcessingError
            ) as incomplete:
                BRIDGE._load_create_receipt(operation, required=False)
            self.assertEqual(
                incomplete.exception.code,
                "BRIDGE_RECOVERY_UNSAFE",
            )

    def test_offline_verifier_is_named_journalled_and_removed(self) -> None:
        container_id = "a" * 64
        image_id = "sha256:" + "b" * 64
        project = "tacua-test"
        state_volume = "tacua-test_tacua-state"
        name = "tacua-state-verifier-123-" + "c" * 12
        calls: list[list[str]] = []

        def fake_docker(argv, **_kwargs):
            arguments = list(argv)
            calls.append(arguments)
            if arguments[:3] == ["container", "start", "--attach"]:
                return subprocess.CompletedProcess(
                    ["docker", *arguments],
                    0,
                    BRIDGE.canonical_json(
                        {
                            "config_digest": "sha256:" + "d" * 64,
                            "deployment_pin_digest": "sha256:" + "e" * 64,
                            "state_directory": BRIDGE.STATE_IN_CONTAINER,
                            "status": "ok",
                        }
                    ),
                    b"",
                )
            return subprocess.CompletedProcess(
                ["docker", *arguments],
                0,
                b"",
                b"",
            )

        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            operation = Path(temporary)
            config = operation / "config.json"
            config.write_text("{}", encoding="utf-8")
            create = BRIDGE._state_verifier_create_argv(
                name=name,
                project=project,
                image_id=image_id,
                state_volume=state_volume,
                config_source=str(config),
            )
            created = mock.Mock()
            inspect_verifier = mock.Mock()
            with (
                mock.patch.object(
                    BRIDGE,
                    "_finish_container_create",
                    return_value={
                        "container_id": container_id,
                        "outcome": "created",
                    },
                ),
                mock.patch.object(BRIDGE, "_clear_create_receipt"),
                mock.patch.object(BRIDGE, "_docker", side_effect=fake_docker),
                mock.patch.object(
                    BRIDGE,
                    "_inspect_container",
                    return_value={
                        "State": {
                            "Error": "",
                            "ExitCode": 0,
                            "OOMKilled": False,
                            "Status": "exited",
                        }
                    },
                ),
                mock.patch.object(
                    BRIDGE,
                    "_inspect_state_verifier",
                    inspect_verifier,
                ),
            ):
                BRIDGE._verify_state_offline(
                    operation=operation,
                    attempt={},
                    name=name,
                    project=project,
                    image_id=image_id,
                    state_volume=state_volume,
                    config_source=str(config),
                    on_created=created,
                )
        created.assert_called_once_with(container_id)
        self.assertEqual(
            [
                call.kwargs["expected_status"]
                for call in inspect_verifier.call_args_list
            ],
            ["created", "exited"],
        )
        rendered = "\n".join(create)
        self.assertNotIn("--rm", create)
        self.assertIn(f"--name\n{name}", rendered)
        self.assertIn(
            f"{BRIDGE.BRIDGE_ROLE_LABEL}={BRIDGE.BRIDGE_VERIFIER_ROLE}",
            rendered,
        )
        self.assertIn(
            f"src={state_volume},dst={BRIDGE.STATE_IN_CONTAINER},volume-nocopy",
            rendered,
        )
        self.assertIn("--env\nTMPDIR=/tmp", rendered)
        self.assertIn(
            f"/tmp:{BRIDGE.STATE_VERIFIER_TMPFS_OPTIONS}",
            create,
        )
        self.assertIn(str(BRIDGE.STATE_VERIFIER_MEMORY_BYTES), create)
        self.assertTrue(
            any(call[:3] == ["container", "rm", "--force"] for call in calls)
        )
        self.assertTrue(
            any(call[:2] == ["container", "ls"] for call in calls)
        )

    def test_offline_verifier_inspection_binds_ephemeral_scratch(self) -> None:
        container_id = "a" * 64
        image_id = "sha256:" + "b" * 64
        project = "tacua-test"
        state_volume = "tacua-test_tacua-state"
        name = "tacua-state-verifier-123-" + "c" * 12
        config_source = "/deployment/config.json"
        inspected = {
            "Config": {
                "Cmd": BRIDGE._state_verifier_command_argv(),
                "Entrypoint": ["/usr/local/bin/python"],
                "Env": [
                    "PYTHONUNBUFFERED=1",
                    "PYTHONDONTWRITEBYTECODE=1",
                    "PYTHONPATH=/app/services/backend/src",
                    "TMPDIR=/tmp",
                ],
                "Healthcheck": {"Test": ["NONE"]},
                "Image": image_id,
                "Labels": {
                    BRIDGE.BRIDGE_LABEL: "true",
                    BRIDGE.BRIDGE_CONTRACT_LABEL: BRIDGE.OPERATION_CONTRACT,
                    BRIDGE.BRIDGE_PROJECT_LABEL: project,
                    BRIDGE.BRIDGE_ROLE_LABEL: BRIDGE.BRIDGE_VERIFIER_ROLE,
                },
                "User": "10001:10001",
            },
            "HostConfig": {
                "AutoRemove": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "DeviceRequests": [],
                "Devices": [],
                "GroupAdd": None,
                "Init": True,
                "IpcMode": "none",
                "LogConfig": {"Config": {}, "Type": "none"},
                "Memory": BRIDGE.STATE_VERIFIER_MEMORY_BYTES,
                "MemorySwap": BRIDGE.STATE_VERIFIER_MEMORY_BYTES,
                "NanoCpus": 2_000_000_000,
                "NetworkMode": "none",
                "PidsLimit": 128,
                "PidMode": "",
                "PortBindings": {},
                "Privileged": False,
                "PublishAllPorts": False,
                "ReadonlyRootfs": True,
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "SecurityOpt": ["no-new-privileges:true"],
                "Tmpfs": {
                    "/tmp": BRIDGE.STATE_VERIFIER_TMPFS_OPTIONS,
                },
                "Ulimits": [
                    {"Name": "nofile", "Hard": 1024, "Soft": 1024}
                ],
                "UsernsMode": "",
                "UTSMode": "",
            },
            "Id": container_id,
            "Image": image_id,
            "Mounts": [
                {
                    "Destination": BRIDGE.STATE_IN_CONTAINER,
                    "Name": state_volume,
                    "RW": True,
                    "Type": "volume",
                },
                {
                    "Destination": BRIDGE.CONFIG_IN_CONTAINER,
                    "RW": False,
                    "Source": config_source,
                    "Type": "bind",
                },
            ],
            "Name": f"/{name}",
            "RestartCount": 0,
            "State": {"Running": False, "Status": "created"},
        }
        arguments = {
            "name": name,
            "project": project,
            "image_id": image_id,
            "state_volume": state_volume,
            "config_source": config_source,
            "expected_status": "created",
        }
        with mock.patch.object(
            BRIDGE,
            "_inspect_container",
            return_value=inspected,
        ):
            BRIDGE._inspect_state_verifier(container_id, **arguments)
            inspected["Config"]["Env"][-1] = "TMPDIR=/var/lib/tacua/tmp"
            with self.assertRaisesRegex(
                BRIDGE.ComposeProcessingError,
                "verifier identity or isolation differs",
            ):
                BRIDGE._inspect_state_verifier(container_id, **arguments)
            inspected["Config"]["Env"][-1] = "TMPDIR=/tmp"
            inspected["HostConfig"]["Tmpfs"]["/tmp"] = (
                "rw,nosuid,nodev,noexec,size=67108864,"
                "uid=10001,gid=10001,mode=0700"
            )
            with self.assertRaisesRegex(
                BRIDGE.ComposeProcessingError,
                "verifier identity or isolation differs",
            ):
                BRIDGE._inspect_state_verifier(container_id, **arguments)

    def test_offline_verifier_attach_failure_removes_exact_container(
        self,
    ) -> None:
        container_id = "a" * 64

        def fake_docker(argv, **_kwargs):
            raise BRIDGE.ComposeProcessingError(
                "BRIDGE_DOCKER_FAILED",
                "synthetic attached verifier interruption",
            )

        created = mock.Mock()
        remove = mock.Mock()
        with (
            mock.patch.object(
                BRIDGE,
                "_finish_container_create",
                return_value={
                    "container_id": container_id,
                    "outcome": "created",
                },
            ),
            mock.patch.object(BRIDGE, "_clear_create_receipt"),
            mock.patch.object(BRIDGE, "_docker", side_effect=fake_docker),
            mock.patch.object(BRIDGE, "_inspect_state_verifier"),
            mock.patch.object(BRIDGE, "_remove_verifier", remove),
            tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary,
        ):
            config = Path(temporary) / "config.json"
            config.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(
                BRIDGE.ComposeProcessingError,
                "synthetic attached verifier interruption",
            ):
                BRIDGE._verify_state_offline(
                    operation=Path(temporary),
                    attempt={},
                    name="tacua-state-verifier-123-" + "c" * 12,
                    project="tacua-test",
                    image_id="sha256:" + "b" * 64,
                    state_volume="tacua-test_tacua-state",
                    config_source=str(config),
                    on_created=created,
                )
        created.assert_called_once_with(container_id)
        remove.assert_called_once_with(container_id)

    def test_recovery_removes_only_the_journal_bound_verifier(self) -> None:
        backend_id = "a" * 64
        verifier_id = "b" * 64
        image_id = "sha256:" + "c" * 64
        verifier_name = "tacua-state-verifier-123-" + "d" * 12
        compose_payload = b'{"name":"tacua-test"}'
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            config = parent / "config.json"
            secret = parent / "admin-secret"
            config.write_text("{}", encoding="utf-8")
            secret.write_bytes(b"synthetic")
            operation = BRIDGE._create_operation_directory(
                parent,
                "tacua-test",
            )
            document = self._journal_document(
                backend_id=backend_id,
                compose_payload=compose_payload,
                config=config,
                image_id=image_id,
                project="tacua-test",
                secret=secret,
            )
            document.update(
                {
                    "phase": "recovery_verifier_created",
                    "verifier_container_id": verifier_id,
                    "verifier_name": verifier_name,
                }
            )
            journal = BRIDGE._write_operation_journal(operation, document)
            inspect_verifier = mock.Mock()
            remove_verifier = mock.Mock()
            with (
                mock.patch.object(
                    BRIDGE,
                    "_recovery_container_candidate",
                    side_effect=(verifier_id, None),
                ),
                mock.patch.object(
                    BRIDGE,
                    "_inspect_container",
                    return_value={
                        "Name": f"/{verifier_name}",
                        "State": {"Status": "running"},
                    },
                ),
                mock.patch.object(
                    BRIDGE,
                    "_inspect_state_verifier",
                    inspect_verifier,
                ),
                mock.patch.object(
                    BRIDGE,
                    "_remove_verifier",
                    remove_verifier,
                ),
            ):
                recovered = BRIDGE._retire_recovery_verifier(
                    operation=operation,
                    journal=journal,
                    project="tacua-test",
                    image_id=image_id,
                    state_volume="tacua-test_tacua-state",
                    config_file=config,
                )
            remove_verifier.assert_called_once_with(verifier_id)
            inspect_verifier.assert_called_once()
            self.assertEqual(
                inspect_verifier.call_args.kwargs["expected_status"],
                "running",
            )
            self.assertIsNone(recovered["verifier_container_id"])
            self.assertIsNone(recovered["verifier_name"])
            self.assertEqual(
                BRIDGE._load_operation_journal(operation),
                recovered,
            )

    def test_recovery_retires_a_dead_journal_bound_verifier(self) -> None:
        backend_id = "a" * 64
        verifier_id = "b" * 64
        image_id = "sha256:" + "c" * 64
        verifier_name = "tacua-state-verifier-123-" + "d" * 12
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            config = parent / "config.json"
            secret = parent / "admin-secret"
            config.write_text("{}", encoding="utf-8")
            secret.write_bytes(b"synthetic")
            operation = BRIDGE._create_operation_directory(parent, "t")
            document = self._journal_document(
                backend_id=backend_id,
                compose_payload=b'{"name":"t"}',
                config=config,
                image_id=image_id,
                project="t",
                secret=secret,
            )
            document.update(
                {
                    "phase": "recovery_verifier_created",
                    "project": "t",
                    "state_volume": "t_tacua-state",
                    "verifier_container_id": verifier_id,
                    "verifier_name": verifier_name,
                }
            )
            journal = BRIDGE._write_operation_journal(operation, document)
            with (
                mock.patch.object(
                    BRIDGE,
                    "_recovery_container_candidate",
                    side_effect=(verifier_id, None),
                ),
                mock.patch.object(
                    BRIDGE,
                    "_inspect_container",
                    return_value={
                        "Name": f"/{verifier_name}",
                        "State": {"Status": "dead"},
                    },
                ),
                mock.patch.object(
                    BRIDGE,
                    "_inspect_state_verifier",
                ) as inspect_verifier,
                mock.patch.object(BRIDGE, "_remove_verifier") as remove,
            ):
                recovered = BRIDGE._retire_recovery_verifier(
                    operation=operation,
                    journal=journal,
                    project="t",
                    image_id=image_id,
                    state_volume="t_tacua-state",
                    config_file=config,
                )
            self.assertEqual(
                inspect_verifier.call_args.kwargs["expected_status"],
                "dead",
            )
            remove.assert_called_once_with(verifier_id)
            self.assertIsNone(recovered["verifier_container_id"])

    def test_recovery_absence_is_a_single_direct_observation(self) -> None:
        with mock.patch.object(
            BRIDGE,
            "_recovery_container_candidates",
            return_value=(),
        ) as discover:
            found = BRIDGE._recovery_container_candidate(
                project="t",
                role=BRIDGE.BRIDGE_VERIFIER_ROLE,
                recorded_name=(
                    "tacua-state-verifier-123-" + "b" * 12
                ),
                recorded_id=None,
            )
        self.assertIsNone(found)
        discover.assert_called_once()

    def test_recovery_discovers_recorded_id_without_role_listing(
        self,
    ) -> None:
        container_id = "a" * 64
        filters: list[str] = []

        def reference(reference_filter, _label):
            filters.append(reference_filter)
            return (
                (container_id,)
                if reference_filter == f"id={container_id}"
                else ()
            )

        with (
            mock.patch.object(
                BRIDGE,
                "_bridge_worker_containers",
                return_value=(),
            ),
            mock.patch.object(
                BRIDGE,
                "_bridge_reference_containers",
                side_effect=reference,
            ),
        ):
            found = BRIDGE._recovery_container_candidates(
                project="t",
                role=BRIDGE.BRIDGE_WORKER_ROLE,
                recorded_name="tacua-processing-123-" + "b" * 12,
                recorded_id=container_id,
            )
        self.assertEqual(found, (container_id,))
        self.assertEqual(
            filters,
            [
                "name=tacua-processing-123-" + "b" * 12,
                f"id={container_id}",
            ],
        )

    def test_recovery_discovery_daemon_error_fails_closed(self) -> None:
        with (
            mock.patch.object(
                BRIDGE,
                "_bridge_worker_containers",
                side_effect=BRIDGE.ComposeProcessingError(
                    "BRIDGE_DOCKER_FAILED",
                    "synthetic daemon error",
                ),
            ),
            self.assertRaises(
                BRIDGE.ComposeProcessingError
            ) as raised,
        ):
            BRIDGE._recovery_container_candidates(
                project="t",
                role=BRIDGE.BRIDGE_WORKER_ROLE,
                recorded_name=None,
                recorded_id=None,
            )
        self.assertEqual(
            raised.exception.code,
            "BRIDGE_RECOVERY_UNSAFE",
        )

    def test_recovery_name_collision_preserves_the_journal(self) -> None:
        backend_id = "a" * 64
        collision_id = "b" * 64
        image_id = "sha256:" + "c" * 64
        recorded_name = "tacua-processing-123-" + "d" * 12
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            config = parent / "config.json"
            secret = parent / "admin-secret"
            config.write_text("{}", encoding="utf-8")
            secret.write_bytes(b"synthetic")
            operation = BRIDGE._create_operation_directory(parent, "t")
            document = self._journal_document(
                backend_id=backend_id,
                compose_payload=b'{"name":"t"}',
                config=config,
                image_id=image_id,
                project="t",
                secret=secret,
            )
            document.update(
                {
                    "phase": "worker_creating",
                    "worker_name": recorded_name,
                }
            )
            journal = BRIDGE._write_operation_journal(operation, document)
            with (
                mock.patch.object(
                    BRIDGE,
                    "_recovery_container_candidate",
                    return_value=collision_id,
                ),
                mock.patch.object(
                    BRIDGE,
                    "_inspect_container",
                    return_value={
                        "Name": "/unrelated-container",
                        "State": {"Status": "created"},
                    },
                ),
                mock.patch.object(
                    BRIDGE,
                    "_remove_worker",
                ) as remove,
                self.assertRaises(
                    BRIDGE.ComposeProcessingError
                ) as raised,
            ):
                BRIDGE._retire_recovery_worker(
                    operation=operation,
                    journal=journal,
                    project="t",
                    image_id=image_id,
                    state_volume="t_tacua-state",
                )
            self.assertEqual(
                raised.exception.code,
                "BRIDGE_RECOVERY_UNSAFE",
            )
            remove.assert_not_called()
            self.assertEqual(
                BRIDGE._load_operation_journal(operation)["worker_name"],
                recorded_name,
            )

    def test_creating_recovery_uses_only_durable_receipt_outcomes(
        self,
    ) -> None:
        backend_id = "a" * 64
        image_id = "sha256:" + "b" * 64
        worker_id = "c" * 64
        worker_name = "tacua-processing-123-" + "d" * 12
        for outcome in ("not_started", "created"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory(
                dir=SHORT_TEMP_ROOT
            ) as temporary:
                parent = Path(temporary).resolve()
                config = parent / "config.json"
                secret = parent / "admin-secret"
                config.write_text("{}", encoding="utf-8")
                secret.write_bytes(b"synthetic")
                operation = BRIDGE._create_operation_directory(parent, "t")
                document = self._journal_document(
                    backend_id=backend_id,
                    compose_payload=b'{"name":"t"}',
                    config=config,
                    image_id=image_id,
                    project="t",
                    secret=secret,
                )
                document.update(
                    {
                        "phase": "worker_creating",
                        "project": "t",
                        "state_volume": "t_tacua-state",
                        "worker_name": worker_name,
                    }
                )
                journal = BRIDGE._write_operation_journal(
                    operation,
                    document,
                )
                self._write_create_receipt(
                    operation,
                    name=worker_name,
                    outcome=outcome,
                    container_id=(
                        worker_id if outcome == "created" else None
                    ),
                )
                with mock.patch.object(
                    BRIDGE,
                    "_recovery_container_candidate",
                    return_value=None,
                ) as discover:
                    recovered = BRIDGE._retire_recovery_worker(
                        operation=operation,
                        journal=journal,
                        project="t",
                        image_id=image_id,
                        state_volume="t_tacua-state",
                    )
                discover.assert_called_once()
                self.assertEqual(recovered["phase"], "worker_exited")
                self.assertFalse(recovered["worker_started"])
                self.assertIsNone(recovered["worker_container_id"])
                self.assertIsNone(recovered["worker_name"])
                self.assertFalse(
                    (operation / BRIDGE.CREATE_RECEIPT_NAME).exists()
                )
                self.assertEqual(
                    BRIDGE._load_operation_journal(operation),
                    recovered,
                )

    def test_creating_recovery_without_negative_proof_fails_closed(
        self,
    ) -> None:
        backend_id = "a" * 64
        image_id = "sha256:" + "b" * 64
        worker_name = "tacua-processing-123-" + "d" * 12
        for outcome in (None, "indeterminate"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory(
                dir=SHORT_TEMP_ROOT
            ) as temporary:
                parent = Path(temporary).resolve()
                config = parent / "config.json"
                secret = parent / "admin-secret"
                config.write_text("{}", encoding="utf-8")
                secret.write_bytes(b"synthetic")
                operation = BRIDGE._create_operation_directory(parent, "t")
                document = self._journal_document(
                    backend_id=backend_id,
                    compose_payload=b'{"name":"t"}',
                    config=config,
                    image_id=image_id,
                    project="t",
                    secret=secret,
                )
                document.update(
                    {
                        "phase": "worker_creating",
                        "project": "t",
                        "state_volume": "t_tacua-state",
                        "worker_name": worker_name,
                    }
                )
                BRIDGE._write_operation_journal(operation, document)
                if outcome is not None:
                    self._write_create_receipt(
                        operation,
                        name=worker_name,
                        outcome=outcome,
                    )
                journal_path = operation / BRIDGE.JOURNAL_NAME
                journal_before = journal_path.read_bytes()
                receipt_path = operation / BRIDGE.CREATE_RECEIPT_NAME
                receipt_before = (
                    receipt_path.read_bytes()
                    if receipt_path.exists()
                    else None
                )
                with (
                    mock.patch.object(
                        BRIDGE,
                        "_recovery_container_candidate",
                        return_value=None,
                    ),
                    self.assertRaises(
                        BRIDGE.ComposeProcessingError
                    ) as raised,
                ):
                    BRIDGE._retire_recovery_worker(
                        operation=operation,
                        journal=BRIDGE._load_operation_journal(operation),
                        project="t",
                        image_id=image_id,
                        state_volume="t_tacua-state",
                    )
                self.assertEqual(
                    raised.exception.code,
                    "BRIDGE_RECOVERY_UNSAFE",
                )
                self.assertEqual(journal_path.read_bytes(), journal_before)
                self.assertEqual(
                    (
                        receipt_path.read_bytes()
                        if receipt_path.exists()
                        else None
                    ),
                    receipt_before,
                )

    def test_positive_candidate_is_journaled_before_recovery_removal(
        self,
    ) -> None:
        backend_id = "a" * 64
        image_id = "sha256:" + "b" * 64
        worker_id = "c" * 64
        worker_name = "tacua-processing-123-" + "d" * 12
        cases = (
            (None, "created", False),
            ("indeterminate", "running", True),
        )
        for receipt_outcome, status, expected_started in cases:
            with (
                self.subTest(
                    receipt=receipt_outcome,
                    status=status,
                ),
                tempfile.TemporaryDirectory(
                    dir=SHORT_TEMP_ROOT
                ) as temporary,
            ):
                parent = Path(temporary).resolve()
                config = parent / "config.json"
                secret = parent / "admin-secret"
                config.write_text("{}", encoding="utf-8")
                secret.write_bytes(b"synthetic")
                operation = BRIDGE._create_operation_directory(parent, "t")
                document = self._journal_document(
                    backend_id=backend_id,
                    compose_payload=b'{"name":"t"}',
                    config=config,
                    image_id=image_id,
                    project="t",
                    secret=secret,
                )
                document.update(
                    {
                        "phase": "worker_creating",
                        "project": "t",
                        "state_volume": "t_tacua-state",
                        "worker_name": worker_name,
                    }
                )
                journal = BRIDGE._write_operation_journal(
                    operation,
                    document,
                )
                if receipt_outcome is not None:
                    self._write_create_receipt(
                        operation,
                        name=worker_name,
                        outcome=receipt_outcome,
                    )
                removed_journal: dict[str, object] = {}

                def remove(_container_id):
                    removed_journal.update(
                        BRIDGE._load_operation_journal(operation)
                    )

                with (
                    mock.patch.object(
                        BRIDGE,
                        "_recovery_container_candidate",
                        side_effect=(worker_id, None),
                    ),
                    mock.patch.object(
                        BRIDGE,
                        "_inspect_container",
                        return_value={
                            "Name": f"/{worker_name}",
                            "State": {"Status": status},
                        },
                    ),
                    mock.patch.object(BRIDGE, "_inspect_worker"),
                    mock.patch.object(
                        BRIDGE,
                        "_remove_worker",
                        side_effect=remove,
                    ),
                ):
                    recovered = BRIDGE._retire_recovery_worker(
                        operation=operation,
                        journal=journal,
                        project="t",
                        image_id=image_id,
                        state_volume="t_tacua-state",
                    )
                self.assertEqual(
                    removed_journal["phase"],
                    (
                        "worker_starting"
                        if expected_started
                        else "worker_created"
                    ),
                )
                self.assertEqual(
                    removed_journal["worker_container_id"],
                    worker_id,
                )
                self.assertEqual(
                    removed_journal["worker_started"],
                    expected_started,
                )
                self.assertEqual(
                    recovered["worker_started"],
                    expected_started,
                )
                self.assertEqual(recovered["phase"], "worker_exited")
                self.assertFalse(
                    (operation / BRIDGE.CREATE_RECEIPT_NAME).exists()
                )

    def test_running_worker_is_marked_started_before_recovery_removal(
        self,
    ) -> None:
        backend_id = "a" * 64
        image_id = "sha256:" + "b" * 64
        worker_id = "c" * 64
        worker_name = "tacua-processing-123-" + "d" * 12
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            config = parent / "config.json"
            secret = parent / "admin-secret"
            config.write_text("{}", encoding="utf-8")
            secret.write_bytes(b"synthetic")
            operation = BRIDGE._create_operation_directory(parent, "t")
            document = self._journal_document(
                backend_id=backend_id,
                compose_payload=b'{"name":"t"}',
                config=config,
                image_id=image_id,
                project="t",
                secret=secret,
            )
            document.update(
                {
                    "phase": "worker_creating",
                    "project": "t",
                    "state_volume": "t_tacua-state",
                    "worker_name": worker_name,
                }
            )
            journal = BRIDGE._write_operation_journal(
                operation,
                document,
            )
            self._write_create_receipt(
                operation,
                name=worker_name,
                outcome="indeterminate",
            )
            with (
                mock.patch.object(
                    BRIDGE,
                    "_recovery_container_candidate",
                    side_effect=(
                        worker_id,
                        BRIDGE.ComposeProcessingError(
                            "BRIDGE_RECOVERY_UNSAFE",
                            "synthetic post-removal interruption",
                        ),
                    ),
                ),
                mock.patch.object(
                    BRIDGE,
                    "_inspect_container",
                    return_value={
                        "Name": f"/{worker_name}",
                        "State": {"Status": "running"},
                    },
                ),
                mock.patch.object(BRIDGE, "_inspect_worker"),
                mock.patch.object(BRIDGE, "_remove_worker"),
                self.assertRaises(BRIDGE.ComposeProcessingError),
            ):
                BRIDGE._retire_recovery_worker(
                    operation=operation,
                    journal=journal,
                    project="t",
                    image_id=image_id,
                    state_volume="t_tacua-state",
                )
            interrupted = BRIDGE._load_operation_journal(operation)
            self.assertEqual(interrupted["phase"], "worker_starting")
            self.assertTrue(interrupted["worker_started"])
            self.assertEqual(
                interrupted["worker_container_id"],
                worker_id,
            )
            self.assertFalse(
                (operation / BRIDGE.CREATE_RECEIPT_NAME).exists()
            )

            with mock.patch.object(
                BRIDGE,
                "_recovery_container_candidate",
                return_value=None,
            ):
                recovered = BRIDGE._retire_recovery_worker(
                    operation=operation,
                    journal=interrupted,
                    project="t",
                    image_id=image_id,
                    state_volume="t_tacua-state",
                )
            self.assertEqual(recovered["phase"], "worker_exited")
            self.assertTrue(recovered["worker_started"])

    def test_verifier_receipt_survives_worker_retirement_order(
        self,
    ) -> None:
        backend_id = "a" * 64
        image_id = "sha256:" + "b" * 64
        verifier_name = "tacua-state-verifier-123-" + "d" * 12
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            config = parent / "config.json"
            secret = parent / "admin-secret"
            config.write_text("{}", encoding="utf-8")
            secret.write_bytes(b"synthetic")
            operation = BRIDGE._create_operation_directory(parent, "t")
            document = self._journal_document(
                backend_id=backend_id,
                compose_payload=b'{"name":"t"}',
                config=config,
                image_id=image_id,
                project="t",
                secret=secret,
            )
            document.update(
                {
                    "phase": "baseline_verifier_creating",
                    "baseline_state_verified": False,
                    "project": "t",
                    "state_volume": "t_tacua-state",
                    "verifier_name": verifier_name,
                }
            )
            journal = BRIDGE._write_operation_journal(operation, document)
            self._write_create_receipt(
                operation,
                name=verifier_name,
                outcome="not_started",
                purpose="baseline",
                role=BRIDGE.BRIDGE_VERIFIER_ROLE,
            )
            after_worker = BRIDGE._retire_recovery_worker(
                operation=operation,
                journal=journal,
                project="t",
                image_id=image_id,
                state_volume="t_tacua-state",
            )
            self.assertTrue(
                (operation / BRIDGE.CREATE_RECEIPT_NAME).exists()
            )
            with mock.patch.object(
                BRIDGE,
                "_recovery_container_candidate",
                return_value=None,
            ):
                recovered = BRIDGE._retire_recovery_verifier(
                    operation=operation,
                    journal=after_worker,
                    project="t",
                    image_id=image_id,
                    state_volume="t_tacua-state",
                    config_file=config,
                )
            self.assertEqual(recovered["phase"], "backend_stopped")
            self.assertFalse(
                (operation / BRIDGE.CREATE_RECEIPT_NAME).exists()
            )

    def test_unbound_positive_receipt_is_preserved_and_fails_closed(
        self,
    ) -> None:
        backend_id = "a" * 64
        image_id = "sha256:" + "b" * 64
        worker_id = "c" * 64
        worker_name = "tacua-processing-123-" + "d" * 12
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            config = parent / "config.json"
            secret = parent / "admin-secret"
            config.write_text("{}", encoding="utf-8")
            secret.write_bytes(b"synthetic")
            operation = BRIDGE._create_operation_directory(parent, "t")
            journal = BRIDGE._write_operation_journal(
                operation,
                self._journal_document(
                    backend_id=backend_id,
                    compose_payload=b'{"name":"t"}',
                    config=config,
                    image_id=image_id,
                    project="t",
                    secret=secret,
                ),
            )
            self._write_create_receipt(
                operation,
                name=worker_name,
                outcome="created",
                container_id=worker_id,
            )
            receipt_path = operation / BRIDGE.CREATE_RECEIPT_NAME
            receipt_before = receipt_path.read_bytes()
            with self.assertRaises(
                BRIDGE.ComposeProcessingError
            ) as raised:
                BRIDGE._retire_recovery_worker(
                    operation=operation,
                    journal=journal,
                    project="t",
                    image_id=image_id,
                    state_volume="t_tacua-state",
                )
            self.assertEqual(
                raised.exception.code,
                "BRIDGE_RECOVERY_UNSAFE",
            )
            self.assertEqual(receipt_path.read_bytes(), receipt_before)

    def test_verifier_mount_resolution_precedes_coordinator_fork(
        self,
    ) -> None:
        backend_id = "a" * 64
        image_id = "sha256:" + "b" * 64
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            config = parent / "config.json"
            secret = parent / "admin-secret"
            config.write_text("{}", encoding="utf-8")
            secret.write_bytes(b"synthetic")
            operation = BRIDGE._create_operation_directory(parent, "t")
            document = self._journal_document(
                backend_id=backend_id,
                compose_payload=b'{"name":"t"}',
                config=config,
                image_id=image_id,
                project="t",
                secret=secret,
            )
            document.update(
                {
                    "baseline_state_verified": False,
                    "phase": "backend_stopped",
                    "project": "t",
                    "state_volume": "t_tacua-state",
                }
            )
            journal = BRIDGE._write_operation_journal(
                operation,
                document,
            )
            before = BRIDGE.signal.pthread_sigmask(
                BRIDGE.signal.SIG_BLOCK,
                set(),
            )
            with (
                mock.patch.object(
                    BRIDGE,
                    "_safe_mount_source",
                    side_effect=BRIDGE.ComposeProcessingError(
                        "BRIDGE_INPUT_INVALID",
                        "synthetic mount resolution failure",
                    ),
                ),
                mock.patch.object(
                    BRIDGE,
                    "_prepare_container_create",
                ) as prepare,
                self.assertRaises(BRIDGE.ComposeProcessingError),
            ):
                BRIDGE._journaled_verify_state(
                    operation=operation,
                    journal=journal,
                    purpose="baseline",
                    final_phase="baseline_verified",
                    project="t",
                    image_id=image_id,
                    state_volume="t_tacua-state",
                    config_file=config,
                    baseline_state_verified=True,
                )
            after = BRIDGE.signal.pthread_sigmask(
                BRIDGE.signal.SIG_BLOCK,
                set(),
            )
            prepare.assert_not_called()
            self.assertEqual(after, before)
            self.assertEqual(
                BRIDGE._load_operation_journal(operation),
                journal,
            )

    def test_verifier_crash_windows_leave_only_durable_conservative_state(
        self,
    ) -> None:
        backend_id = "a" * 64
        verifier_id = "b" * 64
        image_id = "sha256:" + "c" * 64
        cases = ("before_callback", "after_callback", "success")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                dir=SHORT_TEMP_ROOT
            ) as temporary:
                parent = Path(temporary).resolve()
                config = parent / "config.json"
                secret = parent / "admin-secret"
                config.write_text("{}", encoding="utf-8")
                secret.write_bytes(b"synthetic")
                operation = BRIDGE._create_operation_directory(parent, "t")
                document = self._journal_document(
                    backend_id=backend_id,
                    compose_payload=b'{"name":"t"}',
                    config=config,
                    image_id=image_id,
                    project="t",
                    secret=secret,
                )
                document.update(
                    {
                        "baseline_state_verified": False,
                        "phase": "backend_stopped",
                        "project": "t",
                        "state_volume": "t_tacua-state",
                    }
                )
                journal = BRIDGE._write_operation_journal(
                    operation,
                    document,
                )

                def verify(**kwargs):
                    if case == "before_callback":
                        raise BRIDGE.ComposeProcessingError(
                            "BRIDGE_DOCKER_FAILED",
                            "synthetic create interruption",
                        )
                    kwargs["on_created"](verifier_id)
                    if case == "after_callback":
                        raise BRIDGE.ComposeProcessingError(
                            "BRIDGE_DOCKER_FAILED",
                            "synthetic attach interruption",
                        )

                with (
                    mock.patch.object(
                        BRIDGE,
                        "_prepare_container_create",
                        return_value={
                            "gate_descriptor": 100,
                            "name": (
                                "tacua-state-verifier-123-" + "a" * 12
                            ),
                            "pid": 200,
                            "project": "t",
                            "purpose": "baseline",
                            "role": BRIDGE.BRIDGE_VERIFIER_ROLE,
                        },
                    ),
                    mock.patch.object(
                        BRIDGE,
                        "_verify_state_offline",
                        side_effect=verify,
                    ),
                ):
                    if case == "success":
                        result = BRIDGE._journaled_verify_state(
                            operation=operation,
                            journal=journal,
                            purpose="baseline",
                            final_phase="baseline_verified",
                            project="t",
                            image_id=image_id,
                            state_volume="t_tacua-state",
                            config_file=config,
                            baseline_state_verified=True,
                        )
                    else:
                        with self.assertRaises(
                            BRIDGE.ComposeProcessingError
                        ):
                            BRIDGE._journaled_verify_state(
                                operation=operation,
                                journal=journal,
                                purpose="baseline",
                                final_phase="baseline_verified",
                                project="t",
                                image_id=image_id,
                                state_volume="t_tacua-state",
                                config_file=config,
                                baseline_state_verified=True,
                            )
                        result = BRIDGE._load_operation_journal(operation)
                if case == "before_callback":
                    self.assertEqual(
                        result["phase"],
                        "baseline_verifier_creating",
                    )
                    self.assertIsNone(result["verifier_container_id"])
                    self.assertIsNotNone(result["verifier_name"])
                elif case == "after_callback":
                    self.assertEqual(
                        result["phase"],
                        "baseline_verifier_created",
                    )
                    self.assertEqual(
                        result["verifier_container_id"],
                        verifier_id,
                    )
                else:
                    self.assertEqual(result["phase"], "baseline_verified")
                    self.assertTrue(result["baseline_state_verified"])
                    self.assertIsNone(result["verifier_container_id"])
                    self.assertIsNone(result["verifier_name"])

    def test_operation_journal_is_atomic_sealed_and_rejects_tamper(
        self,
    ) -> None:
        backend_id = "a" * 64
        image_id = "sha256:" + "c" * 64
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            config = parent / "config.json"
            secret = parent / "admin-secret"
            config.write_text("{}", encoding="utf-8")
            secret.write_bytes(b"synthetic")
            operation = BRIDGE._create_operation_directory(
                parent,
                "tacua-test",
            )
            document = self._journal_document(
                backend_id=backend_id,
                compose_payload=b'{"name":"tacua-test"}',
                config=config,
                image_id=image_id,
                project="tacua-test",
                secret=secret,
            )
            sealed = BRIDGE._write_operation_journal(
                operation,
                document,
            )
            self.assertEqual(
                BRIDGE._load_operation_journal(operation),
                sealed,
            )
            journal_path = operation / BRIDGE.JOURNAL_NAME
            tampered = json.loads(journal_path.read_text(encoding="utf-8"))
            tampered["baseline_state_verified"] = False
            journal_path.write_text(
                json.dumps(tampered, separators=(",", ":"), sort_keys=True),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                BRIDGE.ComposeProcessingError,
                "malformed or unsealed",
            ):
                BRIDGE._load_operation_journal(operation)

    def test_operation_journal_rejects_sealed_incoherent_phases(
        self,
    ) -> None:
        backend_id = "a" * 64
        verifier_id = "b" * 64
        image_id = "sha256:" + "c" * 64
        worker_id = "d" * 64
        verifier_name = "tacua-state-verifier-123-" + "e" * 12
        worker_name = "tacua-processing-123-" + "f" * 12
        cases = {
            "creating verifier without name": {
                "baseline_state_verified": False,
                "phase": "baseline_verifier_creating",
            },
            "created verifier without id": {
                "baseline_state_verified": False,
                "phase": "baseline_verifier_created",
                "verifier_name": verifier_name,
            },
            "non-verifier carrying identity": {
                "verifier_name": verifier_name,
            },
            "creating worker with id": {
                "phase": "worker_creating",
                "worker_container_id": worker_id,
                "worker_name": worker_name,
            },
            "created worker without id": {
                "phase": "worker_created",
                "worker_name": worker_name,
            },
            "starting worker not marked started": {
                "phase": "worker_starting",
                "worker_container_id": worker_id,
                "worker_name": worker_name,
            },
            "exited worker with partial identity": {
                "phase": "worker_exited",
                "worker_name": worker_name,
                "worker_started": True,
            },
            "prepared journal claims baseline": {
                "phase": "prepared",
            },
            "verified state omits post-worker verification": {
                "phase": "state_verified",
                "worker_started": True,
            },
            "state verification without a worker": {
                "state_verified_after_worker": True,
            },
            "post-worker verifier before worker": {
                "phase": "post_worker_verifier_creating",
                "verifier_name": verifier_name,
            },
        }
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            config = parent / "config.json"
            secret = parent / "admin-secret"
            config.write_text("{}", encoding="utf-8")
            secret.write_bytes(b"synthetic")
            operation = BRIDGE._create_operation_directory(parent, "t")
            base = self._journal_document(
                backend_id=backend_id,
                compose_payload=b'{"name":"t"}',
                config=config,
                image_id=image_id,
                project="t",
                secret=secret,
            )
            for label, changes in cases.items():
                with self.subTest(case=label):
                    document = dict(base)
                    document.update(changes)
                    if label == "created verifier without id":
                        self.assertIsNone(
                            document["verifier_container_id"]
                        )
                    if label == "creating verifier without name":
                        self.assertIsNone(document["verifier_name"])
                    BRIDGE._write_operation_journal(operation, document)
                    with self.assertRaisesRegex(
                        BRIDGE.ComposeProcessingError,
                        "malformed or unsealed",
                    ):
                        BRIDGE._load_operation_journal(operation)
            valid_created = dict(base)
            valid_created.update(
                {
                    "baseline_state_verified": False,
                    "phase": "baseline_verifier_created",
                    "verifier_container_id": verifier_id,
                    "verifier_name": verifier_name,
                }
            )
            sealed = BRIDGE._write_operation_journal(
                operation,
                valid_created,
            )
            self.assertEqual(
                BRIDGE._load_operation_journal(operation),
                sealed,
            )

    def test_verified_source_snapshot_is_exact_private_and_removable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            operation = BRIDGE._create_operation_directory(parent, "t")
            manifest = BRIDGE._bootstrap_snapshot_source(ROOT, operation)
            validated = BRIDGE._bootstrap_validate_snapshot(
                operation,
                manifest["source_digest"],
            )
            self.assertEqual(validated, manifest)
            expected = set(BRIDGE._bootstrap_source_paths(ROOT))
            self.assertEqual(set(manifest["files"]), expected)
            for directory, _pattern in BRIDGE._SOURCE_FAMILIES:
                self.assertTrue(
                    any(
                        path.startswith(directory + "/")
                        for path in expected
                    )
                )
            source_root = operation / BRIDGE._SOURCE_DIRECTORY_NAME
            self.assertEqual(
                stat.S_IMODE(source_root.stat().st_mode),
                0o700,
            )
            for relative in expected:
                self.assertEqual(
                    stat.S_IMODE((source_root / relative).stat().st_mode),
                    0o400,
                )
            BRIDGE._remove_operation_directory(operation)
            self.assertFalse(operation.exists())

    def test_verified_source_snapshot_rejects_mode_and_digest_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            operation = BRIDGE._create_operation_directory(parent, "t")
            manifest = BRIDGE._bootstrap_snapshot_source(ROOT, operation)
            source = (
                operation
                / BRIDGE._SOURCE_DIRECTORY_NAME
                / BRIDGE._SOURCE_EXACT_PATHS[0]
            )
            source.chmod(0o600)
            with self.assertRaises(BRIDGE._SourceBootstrapError):
                BRIDGE._bootstrap_validate_snapshot(
                    operation,
                    manifest["source_digest"],
                )
            source.chmod(0o400)
            original = source.read_bytes()
            source.chmod(0o600)
            source.write_bytes(original + b"\n")
            source.chmod(0o400)
            with self.assertRaises(BRIDGE._SourceBootstrapError):
                BRIDGE._bootstrap_validate_snapshot(
                    operation,
                    manifest["source_digest"],
                )

    def test_image_provenance_program_independently_enumerates_inputs(
        self,
    ) -> None:
        image_id = "sha256:" + "a" * 64
        paths = BRIDGE._host_bundle_paths()
        digest = BRIDGE._bundle_digest(ROOT, paths)
        calls: list[list[str]] = []

        def fake_docker(argv, **_kwargs):
            arguments = list(argv)
            calls.append(arguments)
            compile(arguments[-1], "<image-provenance>", "exec")
            return subprocess.CompletedProcess(
                ["docker", *arguments],
                0,
                BRIDGE.canonical_json(
                    {"digest": digest, "paths": list(paths)}
                ),
                b"",
            )

        with mock.patch.object(BRIDGE, "_docker", side_effect=fake_docker):
            self.assertEqual(
                BRIDGE._verify_host_bundle_matches_image(image_id),
                digest,
            )
        argv = calls[0]
        self.assertEqual(argv[-2], "-c")
        self.assertNotIn(json.dumps(list(paths)), argv)

        def image_with_extra(argv, **_kwargs):
            arguments = list(argv)
            return subprocess.CompletedProcess(
                ["docker", *arguments],
                0,
                BRIDGE.canonical_json(
                    {
                        "digest": digest,
                        "paths": [*paths, "unexpected.py"],
                    }
                ),
                b"",
            )

        with (
            mock.patch.object(
                BRIDGE,
                "_docker",
                side_effect=image_with_extra,
            ),
            self.assertRaisesRegex(
                BRIDGE.ComposeProcessingError,
                "differs from the selected backend image",
            ),
        ):
            BRIDGE._verify_host_bundle_matches_image(image_id)

    def test_cli_bootstrap_reexecs_and_cleans_before_runtime_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="tb-",
            dir=SHORT_TEMP_ROOT,
        ) as temporary:
            parent = Path(temporary).resolve()
            operation = (
                parent / f"{BRIDGE.OPERATION_DIRECTORY_PREFIX}t"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--project",
                    "t",
                    "--compose-json",
                    str(parent / "missing-compose.json"),
                    "--operation-directory",
                    str(parent),
                    "--config-file",
                    str(parent / "missing-config.json"),
                    "--admin-secret-file",
                    str(parent / "missing-secret"),
                    "--isolated-command-file",
                    str(parent / "missing-command.json"),
                    "--run-once",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
                env={
                    "HOME": os.environ.get("HOME", "/nonexistent"),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": os.environ.get("PATH", ""),
                },
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, b"BRIDGE_INPUT_INVALID\n")
            self.assertFalse(operation.exists())

    def test_cli_bootstrap_rejects_duplicate_critical_options(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="tb-",
            dir=SHORT_TEMP_ROOT,
        ) as temporary:
            parent = Path(temporary).resolve()
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--project",
                    "tdupa",
                    "--project",
                    "tdupb",
                    "--compose-json",
                    str(parent / "missing-compose.json"),
                    "--operation-directory",
                    str(parent),
                    "--config-file",
                    str(parent / "missing-config.json"),
                    "--admin-secret-file",
                    str(parent / "missing-secret"),
                    "--isolated-command-file",
                    str(parent / "missing-command.json"),
                    "--run-once",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
                env={
                    "HOME": os.environ.get("HOME", "/nonexistent"),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": os.environ.get("PATH", ""),
                },
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(
                result.stderr,
                b"BRIDGE_SOURCE_BOOTSTRAP_FAILED\n",
            )
            for project in ("tdupa", "tdupb"):
                self.assertFalse(
                    (
                        parent
                        / f"{BRIDGE.OPERATION_DIRECTORY_PREFIX}{project}"
                    ).exists()
                )

    def test_cli_argument_failures_are_stable_and_content_free(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="tb-",
            dir=SHORT_TEMP_ROOT,
        ) as temporary:
            parent = Path(temporary).resolve()
            environment = {
                "HOME": os.environ.get("HOME", "/nonexistent"),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": os.environ.get("PATH", ""),
            }
            complete = [
                "--project",
                "tinput",
                "--compose-json",
                str(parent / "compose.json"),
                "--operation-directory",
                str(parent),
                "--config-file",
                str(parent / "config.json"),
                "--admin-secret-file",
                str(parent / "admin-secret"),
                "--isolated-command-file",
                str(parent / "command.json"),
                "--run-once",
            ]
            cases = (
                (
                    [*complete, "--not-a-real-option", "sensitive-value"],
                    b"BRIDGE_INPUT_INVALID\n",
                ),
                (
                    ["--project", "tinput"],
                    b"BRIDGE_INPUT_INVALID\n",
                ),
                (
                    [
                        "recover",
                        "--project",
                        "tinput",
                        "--operation-directory",
                        str(parent),
                        "--config-file",
                        str(parent / "config.json"),
                        "--admin-secret-file",
                        str(parent / "admin-secret"),
                        "--not-a-real-option",
                        "sensitive-value",
                    ],
                    b"BRIDGE_INPUT_INVALID\n",
                ),
                (
                    ["_broker", "--not-a-real-option", "sensitive-value"],
                    b"BRIDGE_SOURCE_BOOTSTRAP_FAILED\n",
                ),
            )
            for arguments, expected in cases:
                with self.subTest(arguments=arguments[:1]):
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT_PATH), *arguments],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                        timeout=20,
                        env=environment,
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stderr, expected)
                    self.assertNotIn(b"sensitive-value", result.stderr)
            self.assertFalse(
                (
                    parent
                    / f"{BRIDGE.OPERATION_DIRECTORY_PREFIX}tinput"
                ).exists()
            )

    def test_cli_bootstrap_reports_existing_operation_and_busy_lock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="tb-",
            dir=SHORT_TEMP_ROOT,
        ) as temporary:
            parent = Path(temporary).resolve()
            common = [
                "--compose-json",
                str(parent / "missing-compose.json"),
                "--operation-directory",
                str(parent),
                "--config-file",
                str(parent / "missing-config.json"),
                "--admin-secret-file",
                str(parent / "missing-secret"),
                "--isolated-command-file",
                str(parent / "missing-command.json"),
                "--run-once",
            ]
            environment = {
                "HOME": os.environ.get("HOME", "/nonexistent"),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": os.environ.get("PATH", ""),
            }
            existing_project = "texisting"
            operation = BRIDGE._create_operation_directory(
                parent,
                existing_project,
            )
            existing = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "--project",
                    existing_project,
                    *common,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
                env=environment,
            )
            self.assertEqual(existing.returncode, 1)
            self.assertEqual(
                existing.stderr,
                b"BRIDGE_RECOVERY_REQUIRED\n",
            )
            self.assertEqual(tuple(operation.iterdir()), ())

            busy_project = f"tbusy{os.getpid()}"
            lock_path = Path(
                f"/tmp/tacua-compose-processing-{busy_project}.lock"
            )
            descriptor = os.open(
                lock_path,
                os.O_RDWR | os.O_CREAT,
                0o600,
            )
            try:
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                busy = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT_PATH),
                        "--project",
                        busy_project,
                        *common,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=20,
                    env=environment,
                )
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
                lock_path.unlink(missing_ok=True)
            self.assertEqual(busy.returncode, 1)
            self.assertEqual(busy.stderr, b"BRIDGE_BUSY\n")
            self.assertFalse(
                (
                    parent
                    / f"{BRIDGE.OPERATION_DIRECTORY_PREFIX}{busy_project}"
                ).exists()
            )

    def test_bootstrap_and_runtime_cancellation_restore_handlers(
        self,
    ) -> None:
        watched_signals = (
            BRIDGE.signal.SIGHUP,
            BRIDGE.signal.SIGINT,
            BRIDGE.signal.SIGTERM,
        )
        for watched in watched_signals:
            with self.subTest(layer="bootstrap", signal=watched):
                before = {
                    item: BRIDGE.signal.getsignal(item)
                    for item in watched_signals
                }

                def interrupt_bootstrap(_arguments):
                    handler = BRIDGE.signal.getsignal(watched)
                    self.assertTrue(callable(handler))
                    handler(watched, None)

                with (
                    mock.patch.object(
                        BRIDGE,
                        "_bootstrap_dispatch_arguments",
                        side_effect=interrupt_bootstrap,
                    ),
                    mock.patch.object(
                        BRIDGE.sys,
                        "argv",
                        [str(SCRIPT_PATH), "synthetic"],
                    ),
                    mock.patch.object(BRIDGE.os, "umask"),
                    self.assertRaises(
                        BRIDGE._SourceBootstrapError
                    ) as raised,
                ):
                    BRIDGE._bootstrap_dispatch()
                self.assertEqual(raised.exception.code, "BRIDGE_CANCELLED")
                self.assertEqual(
                    {
                        item: BRIDGE.signal.getsignal(item)
                        for item in watched_signals
                    },
                    before,
                )

    def test_bootstrap_handlers_cover_verified_import_startup_gap(
        self,
    ) -> None:
        watched_signals = (
            BRIDGE.signal.SIGHUP,
            BRIDGE.signal.SIGINT,
            BRIDGE.signal.SIGTERM,
        )
        before = {
            item: BRIDGE.signal.getsignal(item)
            for item in watched_signals
        }
        context: dict[str, object] | None = None
        try:
            with (
                mock.patch.object(
                    BRIDGE,
                    "_bootstrap_dispatch_arguments",
                    return_value={},
                ),
                mock.patch.object(
                    BRIDGE.sys,
                    "argv",
                    [str(SCRIPT_PATH), "synthetic"],
                ),
                mock.patch.object(BRIDGE.os, "umask"),
            ):
                context = BRIDGE._bootstrap_dispatch()
            self.assertIsNotNone(context)
            assert context is not None
            self.assertEqual(context["original_signal_handlers"], before)
            self.assertTrue(
                all(
                    callable(BRIDGE.signal.getsignal(item))
                    and BRIDGE.signal.getsignal(item) is not before[item]
                    for item in watched_signals
                )
            )
            with mock.patch.object(
                BRIDGE,
                "_VERIFIED_SOURCE_CONTEXT",
                context,
            ):
                self.assertEqual(
                    BRIDGE._run_with_cancellation(
                        lambda _args: {"status": "ok"},
                        argparse.Namespace(),
                    ),
                    {"status": "ok"},
                )
            self.assertEqual(
                {
                    item: BRIDGE.signal.getsignal(item)
                    for item in watched_signals
                },
                before,
            )
        finally:
            for watched, handler in before.items():
                BRIDGE.signal.signal(watched, handler)

            with self.subTest(layer="runtime", signal=watched):
                before = {
                    item: BRIDGE.signal.getsignal(item)
                    for item in watched_signals
                }

                def interrupt_runtime(_args):
                    handler = BRIDGE.signal.getsignal(watched)
                    self.assertTrue(callable(handler))
                    handler(watched, None)

                with self.assertRaises(
                    BRIDGE.ComposeProcessingError
                ) as raised:
                    BRIDGE._run_with_cancellation(
                        interrupt_runtime,
                        argparse.Namespace(),
                    )
                self.assertEqual(raised.exception.code, "BRIDGE_CANCELLED")
                self.assertEqual(
                    {
                        item: BRIDGE.signal.getsignal(item)
                        for item in watched_signals
                    },
                    before,
                )

    def test_recovery_launcher_rejects_tampered_snapshot_before_runtime(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="tb-",
            dir=SHORT_TEMP_ROOT,
        ) as temporary:
            parent = Path(temporary).resolve()
            operation = BRIDGE._create_operation_directory(parent, "t")
            BRIDGE._bootstrap_snapshot_source(ROOT, operation)
            (operation / BRIDGE.JOURNAL_NAME).write_bytes(b"{}")
            source = (
                operation
                / BRIDGE._SOURCE_DIRECTORY_NAME
                / BRIDGE._SOURCE_EXACT_PATHS[0]
            )
            source.chmod(0o600)
            source.write_bytes(source.read_bytes() + b"\n")
            source.chmod(0o400)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "recover",
                    "--project",
                    "t",
                    "--operation-directory",
                    str(parent),
                    "--config-file",
                    str(parent / "config.json"),
                    "--admin-secret-file",
                    str(parent / "secret"),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
                env={
                    "HOME": os.environ.get("HOME", "/nonexistent"),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": os.environ.get("PATH", ""),
                },
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(
                result.stderr,
                b"BRIDGE_SOURCE_BOOTSTRAP_FAILED\n",
            )
            self.assertTrue(operation.exists())

    def test_recovery_executes_stored_snapshot_after_checkout_changes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="tb-",
            dir=SHORT_TEMP_ROOT,
        ) as temporary:
            parent = Path(temporary).resolve()
            operation = BRIDGE._create_operation_directory(parent, "t")
            BRIDGE._bootstrap_snapshot_source(ROOT, operation)
            (operation / BRIDGE.JOURNAL_NAME).write_bytes(b"{}")
            fake_root = parent / "changed-checkout"
            fake_script = (
                fake_root
                / "services"
                / "backend"
                / "scripts"
                / SCRIPT_PATH.name
            )
            fake_script.parent.mkdir(parents=True)
            live_source = SCRIPT_PATH.read_text(encoding="utf-8")
            marker = "ROOT = Path(__file__).resolve().parents[3]\n"
            self.assertEqual(live_source.count(marker), 1)
            fake_script.write_text(
                live_source.replace(
                    marker,
                    (
                        "raise RuntimeError('LIVE_CHECKOUT_USED')\n"
                        + marker
                    ),
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(fake_script),
                    "recover",
                    "--project",
                    "t",
                    "--operation-directory",
                    str(parent),
                    "--config-file",
                    str(parent / "config.json"),
                    "--admin-secret-file",
                    str(parent / "secret"),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
                env={
                    "HOME": os.environ.get("HOME", "/nonexistent"),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": os.environ.get("PATH", ""),
                },
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(
                result.stderr,
                b"BRIDGE_JOURNAL_INVALID\n",
            )
            self.assertNotIn(b"LIVE_CHECKOUT_USED", result.stderr)

    def test_operation_parent_rejects_unsafe_or_oversized_socket_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            root = Path(temporary).resolve()
            comma_parent = root / "unsafe,parent"
            comma_parent.mkdir(mode=0o700)
            with self.assertRaisesRegex(
                BRIDGE.ComposeProcessingError,
                "Unix socket mount",
            ):
                BRIDGE._operation_path(comma_parent, "tacua-test")

            nested = root
            while len(
                os.fsencode(
                    nested
                    / "tacua-compose-processing-tacua-test"
                    / "processing-bridge.sock"
                )
            ) <= BRIDGE.MAX_UNIX_SOCKET_PATH_BYTES:
                nested /= "long-path-component"
            nested.mkdir(parents=True, mode=0o700, exist_ok=True)
            nested.chmod(0o700)
            with self.assertRaisesRegex(
                BRIDGE.ComposeProcessingError,
                "Unix socket mount",
            ):
                BRIDGE._operation_path(nested, "tacua-test")

    def test_durable_recovery_removes_worker_verifies_and_restarts(
        self,
    ) -> None:
        backend_id = "a" * 64
        worker_id = "b" * 64
        image_id = "sha256:" + "c" * 64
        worker_name = "tacua-processing-123-" + "e" * 12
        compose_payload = b'{"name":"tacua-test"}'
        docker_calls: list[list[str]] = []

        def fake_docker(argv, **_kwargs):
            arguments = list(argv)
            docker_calls.append(arguments)
            stdout = (
                (backend_id + "\n").encode("ascii")
                if "ps" in arguments and "backend" in arguments
                else b""
            )
            return subprocess.CompletedProcess(
                ["docker", *arguments],
                0,
                stdout,
                b"",
            )

        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            config = parent / "config.json"
            secret = parent / "admin-secret"
            config.write_text("{}", encoding="utf-8")
            secret.write_bytes(b"synthetic")
            operation = BRIDGE._create_operation_directory(
                parent,
                "tacua-test",
            )
            (operation / "resolved-compose.json").write_bytes(
                compose_payload
            )
            (operation / "processing-command.json").write_text(
                "{}",
                encoding="utf-8",
            )
            (operation / "processing-bridge.sock").write_bytes(b"placeholder")
            BRIDGE._write_operation_journal(
                operation,
                self._journal_document(
                    backend_id=backend_id,
                    compose_payload=compose_payload,
                    config=config,
                    image_id=image_id,
                    project="tacua-test",
                    secret=secret,
                    worker_id=worker_id,
                    worker_name=worker_name,
                ),
            )
            args = argparse.Namespace(
                admin_secret_file=secret,
                allow_mutable_image=True,
                config_file=config,
                expected_published_port=18080,
                operation_directory=parent,
                project="tacua-test",
            )
            remove_worker = mock.Mock()
            recovery_smoke = mock.Mock()

            def recovery_preflight(*_args, **kwargs):
                self.assertEqual(
                    kwargs["expected_published_port"],
                    18080,
                )
                return {"compose": {"published_port": "18080"}}

            def complete_verifier(**kwargs):
                kwargs["on_created"]("f" * 64)

            verify_state = mock.Mock(side_effect=complete_verifier)
            with (
                mock.patch.multiple(
                    BRIDGE,
                    _acquire_host_lock=mock.Mock(return_value=99),
                    _inspect_backend=mock.Mock(return_value=image_id),
                    _inspect_worker=mock.Mock(),
                    _prepare_container_create=mock.Mock(
                        return_value={
                            "gate_descriptor": 100,
                            "name": (
                                "tacua-state-verifier-123-" + "f" * 12
                            ),
                            "pid": 200,
                            "project": "tacua-test",
                            "purpose": "recovery",
                            "role": BRIDGE.BRIDGE_VERIFIER_ROLE,
                        }
                    ),
                    _release_host_lock=mock.Mock(),
                    _remove_worker=remove_worker,
                    _resolve_deployment=mock.Mock(
                        return_value=(
                            "tacua-test_tacua-state",
                            "tacua-backend:test",
                        )
                    ),
                    _retire_orphaned_broker_socket=mock.Mock(),
                    _smoke_restarted_backend=recovery_smoke,
                    _verify_host_bundle_matches_image=mock.Mock(
                        return_value="sha256:" + "d" * 64
                    ),
                    _verify_state_offline=verify_state,
                    _volume_consumers=mock.Mock(
                        return_value={backend_id}
                    ),
                    _recovery_container_candidate=mock.Mock(
                        side_effect=(worker_id, None)
                    ),
                    _wait_backend_healthy=mock.Mock(),
                    deployment_preflight=mock.Mock(
                        side_effect=recovery_preflight
                    ),
                ),
                mock.patch.object(BRIDGE, "_docker", side_effect=fake_docker),
                mock.patch.object(
                    BRIDGE,
                    "_inspect_container",
                    side_effect=lambda identifier: (
                        {
                            "Name": f"/{worker_name}",
                            "State": {"Status": "running"},
                        }
                        if identifier == worker_id
                        else {"State": {"Status": "exited"}}
                    ),
                ),
            ):
                result = BRIDGE.recover_compose_processing(args)
            self.assertEqual(result, {"status": "recovered"})
            remove_worker.assert_called_once_with(worker_id)
            self.assertEqual(
                recovery_smoke.call_args.args[2],
                "18080",
            )
            verify_state.assert_called_once()
            self.assertEqual(
                verify_state.call_args.kwargs["project"],
                "tacua-test",
            )
            self.assertRegex(
                verify_state.call_args.kwargs["name"],
                r"^tacua-state-verifier-[0-9]+-[a-f0-9]{12}$",
            )
            self.assertFalse(operation.exists())
            rendered = [" ".join(call) for call in docker_calls]
            self.assertTrue(any(" start backend" in call for call in rendered))

    def test_journal_free_recovery_clears_only_pre_effect_operation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            operation = BRIDGE._create_operation_directory(
                parent,
                "tacua-test",
            )
            (operation / "resolved-compose.json").write_text(
                "{}",
                encoding="utf-8",
            )
            args = argparse.Namespace(
                admin_secret_file=parent / "unused-secret",
                allow_mutable_image=True,
                config_file=parent / "unused-config",
                operation_directory=parent,
                project="tacua-test",
            )
            with mock.patch.multiple(
                BRIDGE,
                _acquire_host_lock=mock.Mock(return_value=99),
                _bridge_verifier_containers=mock.Mock(return_value=()),
                _bridge_worker_containers=mock.Mock(return_value=()),
                _release_host_lock=mock.Mock(
                    side_effect=OSError(
                        "synthetic post-commit lock release failure"
                    )
                ),
            ):
                result = BRIDGE.recover_compose_processing(args)
            self.assertEqual(
                result,
                {"status": "no_effect_recovered"},
            )
            self.assertFalse(operation.exists())

    def test_automatic_recovery_discards_incomplete_journal_update(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            operation = BRIDGE._create_operation_directory(parent, "t")
            incomplete = operation / BRIDGE.JOURNAL_NEXT_NAME
            incomplete.write_bytes(b"{}")
            incomplete.chmod(0o600)
            sentinel = BRIDGE.ComposeProcessingError(
                "BRIDGE_TEST_SENTINEL",
                "stop after the incomplete update check",
            )

            def stop_after_discard(_operation):
                self.assertFalse(incomplete.exists())
                raise sentinel

            with (
                mock.patch.object(
                    BRIDGE,
                    "_load_operation_journal",
                    side_effect=stop_after_discard,
                ),
                self.assertRaises(BRIDGE.ComposeProcessingError) as raised,
            ):
                BRIDGE._recover_backend(
                    operation=operation,
                    journal={"contract_version": BRIDGE.OPERATION_CONTRACT},
                    backend_container_id="a" * 64,
                    image_id="sha256:" + "b" * 64,
                    configured_image="tacua-backend:test",
                    state_volume="t_tacua-state",
                    project="t",
                    compose_prefix=("compose",),
                    compose_snapshot=operation / "resolved-compose.json",
                    compose_digest="sha256:" + "c" * 64,
                    published_port="18080",
                    config_file=parent / "config.json",
                    admin_secret_file=parent / "admin-secret",
                    config_identity={},
                    secret_identity={},
                )
            self.assertEqual(
                raised.exception.code,
                "BRIDGE_TEST_SENTINEL",
            )

    def test_operation_cleanup_commits_journal_removal_first(self) -> None:
        with tempfile.TemporaryDirectory(dir=SHORT_TEMP_ROOT) as temporary:
            parent = Path(temporary).resolve()
            operation = BRIDGE._create_operation_directory(parent, "t")
            BRIDGE._bootstrap_snapshot_source(ROOT, operation)
            (operation / BRIDGE.JOURNAL_NAME).write_bytes(b"{}")
            (operation / BRIDGE.JOURNAL_NAME).chmod(0o600)
            failure = BRIDGE.ComposeProcessingError(
                "BRIDGE_CLEANUP_FAILED",
                "synthetic source cleanup interruption",
            )
            with (
                mock.patch.object(
                    BRIDGE,
                    "_remove_source_tree",
                    side_effect=failure,
                ),
                self.assertRaises(BRIDGE.ComposeProcessingError),
            ):
                BRIDGE._remove_operation_directory(operation)
            self.assertFalse(
                (operation / BRIDGE.JOURNAL_NAME).exists()
            )
            self.assertTrue(operation.exists())

    @unittest.skipUnless(
        hasattr(socket, "SCM_RIGHTS") and hasattr(os, "fork"),
        "Unix descriptor passing is required",
    )
    def test_private_socket_bridge_round_trip_uses_existing_runner_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child_output = root / "child-output"
            child_output.mkdir(mode=0o700)
            evidence = b"synthetic descriptor-only evidence"
            evidence_path = root / "evidence.bin"
            evidence_path.write_bytes(evidence)
            input_target = 100
            evidence_target = 101
            for target in (input_target, evidence_target):
                try:
                    os.close(target)
                except OSError:
                    pass
            input_document = {
                "capture": {
                    "diagnostics": [],
                    "segments": [
                        {
                            "content_digest": "sha256:" + "c" * 64,
                            "read_only_path": f"/dev/fd/{evidence_target}",
                        }
                    ],
                },
                "contract_version": "tacua.local-processing-input@1.0.0",
                "input_digest": "sha256:" + "d" * 64,
            }
            input_path = root / "input.json"
            input_bytes = CLIENT.canonical_json(input_document)
            input_path.write_bytes(input_bytes)
            input_source = os.open(input_path, os.O_RDONLY)
            evidence_source = os.open(evidence_path, os.O_RDONLY)
            result_read, result_write = os.pipe()
            broker_socket, client_socket = socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_STREAM,
            )
            child = os.fork()
            if child == 0:  # pragma: no cover - assertions happen in parent
                try:
                    os.close(result_read)
                    broker_socket.close()
                    os.dup2(input_source, input_target, inheritable=True)
                    os.dup2(evidence_source, evidence_target, inheritable=True)
                    if input_source not in {input_target, evidence_target}:
                        os.close(input_source)
                    if evidence_source not in {input_target, evidence_target}:
                        os.close(evidence_source)
                    targets = CLIENT.adapter_descriptor_targets(
                        Path(f"/dev/fd/{input_target}")
                    )
                    CLIENT.send_frame(
                        client_socket,
                        {
                            "contract_version": CLIENT.REQUEST_CONTRACT,
                            "descriptor_targets": list(targets),
                        },
                    )
                    CLIENT.send_descriptor_batches(client_socket, targets)
                    response = CLIENT.receive_frame(client_socket)
                    result = CLIENT.receive_success_response(
                        client_socket,
                        response,
                        child_output,
                    )
                    client_socket.close()
                    os.write(result_write, result)
                    os.close(result_write)
                    os._exit(0)
                except BaseException:
                    os._exit(1)

            os.close(result_write)
            os.close(input_source)
            os.close(evidence_source)
            client_socket.close()
            expected_result = CLIENT.canonical_json(
                {
                    "contract_version": "synthetic.result@1.0.0",
                    "status": "ok",
                }
            )

            def fake_run(_command, received_input, output_directory):
                self.assertEqual(received_input.read_bytes(), input_bytes)
                self.assertEqual(
                    Path(f"/dev/fd/{evidence_target}").read_bytes(),
                    evidence,
                )
                (output_directory / "preview.png").write_bytes(b"preview")
                return expected_result

            try:
                with (
                    mock.patch.object(
                        BRIDGE.RUNNER,
                        "validate_outer_timeout_environment",
                    ),
                    mock.patch.object(
                        BRIDGE.RUNNER,
                        "load_command",
                        return_value={"synthetic": True},
                    ),
                    mock.patch.object(
                        BRIDGE.RUNNER,
                        "run",
                        side_effect=fake_run,
                    ),
                ):
                    BRIDGE._run_one_request(
                        broker_socket,
                        {"synthetic": True},
                    )
            finally:
                broker_socket.close()

            returned = bytearray()
            while block := os.read(result_read, 65_536):
                returned.extend(block)
            os.close(result_read)
            _pid, wait_status = os.waitpid(child, 0)
            self.assertTrue(os.WIFEXITED(wait_status))
            self.assertEqual(os.WEXITSTATUS(wait_status), 0)
            self.assertEqual(bytes(returned), expected_result)
            self.assertEqual(
                (child_output / "preview.png").read_bytes(),
                b"preview",
            )

    def test_worker_create_has_only_narrow_socket_and_no_docker_socket(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            secret = root / "admin-secret"
            command = root / "processing-command.json"
            socket_path = root / "bridge.sock"
            config.write_text("{}", encoding="utf-8")
            secret.write_bytes(b"synthetic")
            BRIDGE._write_outer_command(
                command,
                "tacua.local-processing-command@1.0.0",
            )
            socket_path.write_bytes(b"synthetic socket mount placeholder")
            argv = BRIDGE._worker_create_argv(
                name="tacua-processing-test",
                project="tacua-test",
                image_id="sha256:" + "a" * 64,
                state_volume="tacua-test_tacua-state",
                config_file=config,
                admin_secret_file=secret,
                command_file=command,
                socket_path=socket_path,
                worker_id="worker_test",
                run_once=True,
                max_stages=1,
            )
            rendered = "\n".join(argv)
            self.assertNotIn("docker.sock", rendered)
            self.assertIn("--network\nnone", rendered)
            self.assertIn("--read-only", argv)
            self.assertIn("--init", argv)
            self.assertIn("--log-driver\nnone", rendered)
            self.assertIn("--cap-drop\nALL", rendered)
            self.assertIn(
                f"dst={BRIDGE.BRIDGE_SOCKET_IN_CONTAINER},readonly",
                rendered,
            )
            self.assertIn(
                f"dst={BRIDGE.STATE_IN_CONTAINER},volume-nocopy",
                rendered,
            )
            command_document = command.read_text(encoding="utf-8")
            self.assertIn(
                BRIDGE_CLIENT_MODULE := CLIENT.__name__,
                command_document,
            )
            self.assertEqual(
                BRIDGE_CLIENT_MODULE,
                "tacua_backend.processing_bridge",
            )

    def test_worker_inspection_rejects_command_or_docker_socket_drift(
        self,
    ) -> None:
        container_id = "a" * 64
        image_id = "sha256:" + "b" * 64
        state_volume = "tacua-test_tacua-state"
        name = "tacua-processing-test"
        project = "tacua-test"
        mounts = [
            {
                "Destination": BRIDGE.STATE_IN_CONTAINER,
                "Name": state_volume,
                "RW": True,
                "Type": "volume",
            },
            *[
                {
                    "Destination": destination,
                    "RW": False,
                    "Source": f"/private/{index}",
                    "Type": "bind",
                }
                for index, destination in enumerate(
                    (
                        BRIDGE.CONFIG_IN_CONTAINER,
                        BRIDGE.SECRET_IN_CONTAINER,
                        BRIDGE.BRIDGE_COMMAND_IN_CONTAINER,
                        BRIDGE.BRIDGE_SOCKET_IN_CONTAINER,
                    )
                )
            ],
        ]
        inspected = {
            "Config": {
                "Cmd": BRIDGE._worker_command_argv(
                    worker_id="worker_test",
                    run_once=True,
                    max_stages=1,
                ),
                "Entrypoint": ["/usr/local/bin/python"],
                "Healthcheck": {"Test": ["NONE"]},
                "Image": image_id,
                "Labels": {
                    BRIDGE.BRIDGE_CONTRACT_LABEL: CLIENT.REQUEST_CONTRACT,
                    BRIDGE.BRIDGE_LABEL: "true",
                    BRIDGE.BRIDGE_PROJECT_LABEL: project,
                    BRIDGE.BRIDGE_ROLE_LABEL: BRIDGE.BRIDGE_WORKER_ROLE,
                },
                "User": "10001:10001",
            },
            "HostConfig": {
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "IpcMode": "none",
                "Init": True,
                "LogConfig": {"Config": {}, "Type": "none"},
                "Memory": 4_294_967_296,
                "MemorySwap": 4_294_967_296,
                "NanoCpus": 2_000_000_000,
                "NetworkMode": "none",
                "PidsLimit": 128,
                "PidMode": "",
                "PortBindings": {},
                "Privileged": False,
                "PublishAllPorts": False,
                "ReadonlyRootfs": True,
                "RestartPolicy": {"MaximumRetryCount": 0, "Name": "no"},
                "SecurityOpt": ["no-new-privileges:true"],
                "Tmpfs": {"/tmp": BRIDGE.WORKER_TMPFS_OPTIONS},
                "UTSMode": "",
                "Ulimits": [
                    {"Hard": 1024, "Name": "nofile", "Soft": 1024}
                ],
                "UsernsMode": "",
                "AutoRemove": False,
                "DeviceRequests": None,
                "Devices": [],
                "GroupAdd": [],
            },
            "Id": container_id,
            "Image": image_id,
            "Mounts": mounts,
            "Name": f"/{name}",
            "RestartCount": 0,
            "State": {"Running": False, "Status": "created"},
        }
        with mock.patch.object(
            BRIDGE,
            "_inspect_container",
            return_value=inspected,
        ):
            BRIDGE._inspect_worker(
                container_id,
                name=name,
                project=project,
                image_id=image_id,
                state_volume=state_volume,
                expected_status="created",
                expected_command=BRIDGE._worker_command_argv(
                    worker_id="worker_test",
                    run_once=True,
                    max_stages=1,
                ),
            )
            inspected["Config"]["Cmd"] = ["unexpected"]
            with self.assertRaisesRegex(
                BRIDGE.ComposeProcessingError,
                "one-shot worker isolation",
            ):
                BRIDGE._inspect_worker(
                    container_id,
                    name=name,
                    project=project,
                    image_id=image_id,
                    state_volume=state_volume,
                    expected_status="created",
                    expected_command=BRIDGE._worker_command_argv(
                        worker_id="worker_test",
                        run_once=True,
                        max_stages=1,
                    ),
                )
            inspected["Config"]["Cmd"] = BRIDGE._worker_command_argv(
                worker_id="worker_test",
                run_once=True,
                max_stages=1,
            )
            inspected["Mounts"].append(
                {
                    "Destination": "/tmp",
                    "RW": True,
                    "Type": "tmpfs",
                }
            )
            BRIDGE._inspect_worker(
                container_id,
                name=name,
                project=project,
                image_id=image_id,
                state_volume=state_volume,
                expected_status="created",
                expected_command=BRIDGE._worker_command_argv(
                    worker_id="worker_test",
                    run_once=True,
                    max_stages=1,
                ),
            )
            inspected["Mounts"].append(
                {
                    "Destination": "/var/run/docker.sock",
                    "RW": True,
                    "Source": "/var/run/docker.sock",
                    "Type": "bind",
                }
            )
            with self.assertRaisesRegex(
                BRIDGE.ComposeProcessingError,
                "one-shot worker isolation",
            ):
                BRIDGE._inspect_worker(
                    container_id,
                    name=name,
                    project=project,
                    image_id=image_id,
                    state_volume=state_volume,
                    expected_status="created",
                    expected_command=BRIDGE._worker_command_argv(
                        worker_id="worker_test",
                        run_once=True,
                        max_stages=1,
                    ),
                )

    def test_lifecycle_stops_processes_verifies_restarts_and_smokes(self) -> None:
        (
            result,
            calls,
            verify_state,
            smoke,
            _wait_healthy,
            raised,
        ) = self._exercise_lifecycle(worker_failure=None)
        self.assertIsNone(raised)
        assert result is not None
        self.assertEqual(result["status"], "ok")
        rendered = [" ".join(call) for call in calls]
        stop_index = next(
            index for index, call in enumerate(rendered) if " stop backend" in call
        )
        create_index = next(
            index
            for index, call in enumerate(rendered)
            if call == "container create"
        )
        start_index = next(
            index for index, call in enumerate(rendered) if " start backend" in call
        )
        self.assertLess(stop_index, create_index)
        self.assertLess(create_index, start_index)
        self.assertEqual(verify_state.call_count, 2)
        smoke.assert_called_once()
        self.assertEqual(
            smoke.call_args.kwargs["origin_override"],
            "http://127.0.0.1:18080",
        )

    def test_prejournal_failure_reports_content_free_stage(self) -> None:
        (
            result,
            calls,
            verify_state,
            smoke,
            wait_healthy,
            raised,
        ) = self._exercise_lifecycle(
            worker_failure=None,
            preflight_failure=BRIDGE.OperatorError("synthetic secret detail"),
        )
        self.assertIsNone(result)
        self.assertIsNotNone(raised)
        assert raised is not None
        self.assertEqual(
            raised.code,
            "BRIDGE_DEPLOYMENT_PREFLIGHT_FAILED",
        )
        self.assertNotIn("synthetic", str(raised))
        self.assertEqual(calls, [])
        verify_state.assert_not_called()
        smoke.assert_not_called()
        wait_healthy.assert_not_called()

    def test_failed_worker_reverifies_before_recovery_restart(self) -> None:
        (
            _result,
            calls,
            verify_state,
            smoke,
            _wait_healthy,
            raised,
        ) = self._exercise_lifecycle(
            worker_failure=BRIDGE.ComposeProcessingError(
                "BRIDGE_WORKER_FAILED",
                "synthetic failure",
            )
        )
        self.assertIsNotNone(raised)
        assert raised is not None
        self.assertEqual(raised.code, "BRIDGE_WORKER_FAILED")
        rendered = [" ".join(call) for call in calls]
        self.assertTrue(any(" start backend" in call for call in rendered))
        self.assertEqual(verify_state.call_count, 2)
        smoke.assert_called_once()

    def test_unhealthy_running_backend_is_reverified_before_error_returns(
        self,
    ) -> None:
        restart_error = BRIDGE.ComposeProcessingError(
            "BRIDGE_RESTART_FAILED",
            "synthetic unhealthy backend",
        )
        (
            _result,
            calls,
            verify_state,
            smoke,
            wait_healthy,
            raised,
        ) = self._exercise_lifecycle(
            worker_failure=None,
            recovery_backend_status="running",
            wait_effect=[restart_error, None],
        )
        self.assertIsNotNone(raised)
        assert raised is not None
        self.assertEqual(raised.code, "BRIDGE_RESTART_FAILED")
        self.assertEqual(wait_healthy.call_count, 2)
        self.assertEqual(verify_state.call_count, 2)
        smoke.assert_called_once()
        starts = [
            call
            for call in calls
            if " start backend" in " ".join(call)
        ]
        self.assertEqual(len(starts), 1)

    def test_failed_recovery_restart_surfaces_stable_critical_error(
        self,
    ) -> None:
        restart_error = BRIDGE.ComposeProcessingError(
            "BRIDGE_RESTART_FAILED",
            "synthetic unhealthy backend",
        )
        (
            _result,
            calls,
            verify_state,
            smoke,
            wait_healthy,
            raised,
        ) = self._exercise_lifecycle(
            worker_failure=None,
            recovery_backend_status="exited",
            wait_effect=[restart_error, restart_error],
        )
        self.assertIsNotNone(raised)
        assert raised is not None
        self.assertEqual(raised.code, "BRIDGE_RECOVERY_FAILED")
        self.assertEqual(wait_healthy.call_count, 2)
        self.assertEqual(verify_state.call_count, 2)
        smoke.assert_not_called()
        starts = [
            call
            for call in calls
            if " start backend" in " ".join(call)
        ]
        self.assertEqual(len(starts), 2)

    def test_failed_post_worker_verification_blocks_restart_critically(
        self,
    ) -> None:
        (
            _result,
            calls,
            verify_state,
            smoke,
            wait_healthy,
            raised,
        ) = self._exercise_lifecycle(
            worker_failure=BRIDGE.ComposeProcessingError(
                "BRIDGE_WORKER_FAILED",
                "synthetic worker failure",
            ),
            verify_effect=[
                None,
                BRIDGE.ComposeProcessingError(
                    "BRIDGE_STATE_INVALID",
                    "synthetic state verification failure",
                ),
            ],
        )
        self.assertIsNotNone(raised)
        assert raised is not None
        self.assertEqual(raised.code, "BRIDGE_RECOVERY_FAILED")
        self.assertEqual(verify_state.call_count, 2)
        wait_healthy.assert_not_called()
        smoke.assert_not_called()
        self.assertFalse(
            any(" start backend" in " ".join(call) for call in calls)
        )

    def test_post_commit_lock_release_failure_does_not_require_recovery(
        self,
    ) -> None:
        (
            result,
            calls,
            verify_state,
            smoke,
            wait_healthy,
            raised,
        ) = self._exercise_lifecycle(
            worker_failure=None,
            release_effect=OSError("synthetic lock cleanup failure"),
        )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["status"], "ok")
        self.assertIsNone(raised)
        self.assertEqual(verify_state.call_count, 2)
        wait_healthy.assert_called_once()
        smoke.assert_called_once()
        starts = [
            call
            for call in calls
            if " start backend" in " ".join(call)
        ]
        self.assertEqual(len(starts), 1)


if __name__ == "__main__":
    unittest.main()
