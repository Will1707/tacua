# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
RUNNER_PATH = ROOT / "services" / "backend" / "scripts" / "run_isolated_processor.py"


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


RUNNER = load_module(
    "tacua_isolated_processor_runner",
    RUNNER_PATH,
)
PROFILE = load_module(
    "tacua_isolated_processor_profile",
    ROOT / "services" / "backend" / "scripts" / "verify_isolated_processor_profile.py",
)
INTEGRATION = load_module(
    "tacua_isolated_processor_integration",
    ROOT / "services" / "backend" / "scripts" / "run_synthetic_isolated_processor_integration.py",
)


def sealed_input(evidence_path: str, evidence: bytes = b"synthetic evidence") -> dict:
    value = {
        "binding": {"job_id": "job_synthetic"},
        "capture": {
            "diagnostics": [],
            "segments": [
                {
                    "content_digest": "sha256:" + hashlib.sha256(evidence).hexdigest(),
                    "read_only_path": evidence_path,
                    "segment_id": "segment_synthetic",
                }
            ],
        },
        "contract_version": RUNNER.SOURCE_INPUT_CONTRACT,
        "input_digest": "sha256:" + "0" * 64,
        "job": {
            "job_id": "job_synthetic",
            "pipeline": {"pipeline_version": RUNNER.LEGACY_PIPELINE_VERSION},
        },
    }
    subject = copy.deepcopy(value)
    subject.pop("input_digest")
    value["input_digest"] = "sha256:" + hashlib.sha256(RUNNER.canonical_json(subject)).hexdigest()
    return value


def sealed_input_v11(
    evidence_path: str,
    evidence: bytes = b"synthetic evidence",
    *,
    stage_name: str = "align",
    transcript_text: str = "PRIVATE_ISOLATED_TRANSCRIPT_SENTINEL",
) -> dict:
    job_id = "job_artifact_synthetic"
    session_id = "session_artifact_synthetic"
    created_at = "2026-07-23T10:02:07Z"
    derived_data_expires_at = "2026-08-22T10:02:06Z"
    content_digest = "sha256:" + hashlib.sha256(evidence).hexdigest()
    source_segment = {
        "segment_id": "segment_artifact_synthetic",
        "sequence": 0,
        "content_digest": content_digest,
        "start_ms": 0,
        "end_ms": 1_000,
    }
    payload = {
        "contract_version": RUNNER.TRANSCRIPT_CONTRACT,
        "language_tag": "en-GB",
        "speech_status": "detected",
        "source_segments": [source_segment],
        "spans": [
            {
                "segment_id": source_segment["segment_id"],
                "start_ms": 0,
                "end_ms": 1_000,
                "text": transcript_text,
            }
        ],
    }
    artifact = {
        "contract_version": RUNNER.PROCESSING_ARTIFACT_CONTRACT,
        "media_type": RUNNER.PROCESSING_ARTIFACT_MEDIA_TYPE,
        "artifact_id": RUNNER._processing_artifact_id(
            job_id, "transcribe", "transcript"
        ),
        "artifact_kind": "transcript",
        "organization_id": "organization_synthetic",
        "project_id": "project_synthetic",
        "session_id": session_id,
        "job_id": job_id,
        "stage_name": "transcribe",
        "checkpoint_job_version": 3,
        "created_at": created_at,
        "derived_data_expires_at": derived_data_expires_at,
        "payload": payload,
        "artifact_digest": "sha256:" + "0" * 64,
    }
    artifact_subject = copy.deepcopy(artifact)
    artifact_subject.pop("artifact_digest")
    artifact["artifact_digest"] = "sha256:" + hashlib.sha256(
        RUNNER.canonical_json(artifact_subject)
    ).hexdigest()
    transcribe_state = "succeeded" if stage_name == "align" else "running"
    stages = [
        {
            "name": "transcribe",
            "state": transcribe_state,
            "attempt_count": 1,
            "started_at": "2026-07-23T10:02:06Z",
            "completed_at": created_at if stage_name == "align" else None,
            "detail": (
                "The transcript artifact was published atomically."
                if stage_name == "align"
                else None
            ),
        },
        {
            "name": "align",
            "state": "running" if stage_name == "align" else "pending",
            "attempt_count": 1 if stage_name == "align" else 0,
            "started_at": "2026-07-23T10:02:08Z" if stage_name == "align" else None,
            "completed_at": None,
            "detail": None,
        },
        *[
            {
                "name": name,
                "state": "pending",
                "attempt_count": 0,
                "started_at": None,
                "completed_at": None,
                "detail": None,
            }
            for name in ("correlate", "research", "generate_tickets")
        ],
    ]
    value = {
        "binding": {
            "organization_id": "organization_synthetic",
            "project_id": "project_synthetic",
            "session_id": session_id,
            "job_id": job_id,
            "job_version": 4 if stage_name == "align" else 2,
            "stage_name": stage_name,
        },
        "capture": {
            "derived_data_expires_at": derived_data_expires_at,
            "diagnostics": [],
            "manifest": {
                "segments": [
                    {
                        "availability": "available",
                        "content": {"content_digest": content_digest},
                        "segment_id": source_segment["segment_id"],
                        "sequence": source_segment["sequence"],
                        "time_range": {"start_ms": 0, "end_ms": 1_000},
                    }
                ]
            },
            "segments": [
                {
                    "content_digest": content_digest,
                    "read_only_path": evidence_path,
                    "segment_id": source_segment["segment_id"],
                }
            ],
        },
        "contract_version": RUNNER.SOURCE_INPUT_CONTRACT_V11,
        "input_digest": "sha256:" + "0" * 64,
        "job": {
            "job_id": job_id,
            "pipeline": {
                "pipeline_version": RUNNER.ARTIFACT_PIPELINE_VERSION,
                "stages": stages,
            },
        },
        "stage_inputs": {
            "artifacts": [artifact] if stage_name == "align" else []
        },
    }
    subject = copy.deepcopy(value)
    subject.pop("input_digest")
    value["input_digest"] = "sha256:" + hashlib.sha256(
        RUNNER.canonical_json(subject)
    ).hexdigest()
    return value


def reseal_source_input(value: dict) -> dict:
    subject = copy.deepcopy(value)
    subject.pop("input_digest")
    value["input_digest"] = "sha256:" + hashlib.sha256(
        RUNNER.canonical_json(subject)
    ).hexdigest()
    return value


def reseal_stage_artifact(artifact: dict) -> dict:
    subject = copy.deepcopy(artifact)
    subject.pop("artifact_digest")
    artifact["artifact_digest"] = "sha256:" + hashlib.sha256(
        RUNNER.canonical_json(subject)
    ).hexdigest()
    return artifact


def output_envelope(result: dict, previews: list[tuple[str, bytes]] | None = None) -> bytes:
    rendered_previews = []
    for name, contents in previews or []:
        import base64

        rendered_previews.append(
            {
                "content_base64": base64.b64encode(contents).decode("ascii"),
                "content_digest": "sha256:" + hashlib.sha256(contents).hexdigest(),
                "name": name,
                "size_bytes": len(contents),
            }
        )
    result_bytes = RUNNER.canonical_json(result)
    return RUNNER.canonical_json(
        {
            "contract_version": RUNNER.OUTPUT_CONTRACT,
            "previews": rendered_previews,
            "result": result,
            "result_digest": "sha256:" + hashlib.sha256(result_bytes).hexdigest(),
        }
    )


def isolated_command(model: Path) -> dict:
    return {
        "argv": [
            "/opt/tacua/processor",
            "--input",
            RUNNER.INPUT_PLACEHOLDER,
            "--model",
            RUNNER.MODEL_PLACEHOLDER,
        ],
        "contract_version": RUNNER.COMMAND_CONTRACT,
        "image": "sha256:" + "a" * 64,
        "model_digest": "sha256:" + hashlib.sha256(model.read_bytes()).hexdigest(),
        "model_id": "synthetic-model",
        "model_path": str(model),
        "timeout_seconds": 30,
    }


def resolved_profile() -> dict:
    return {
        "services": {
            PROFILE.SERVICE: {
                "profiles": ["private-pilot"],
                "image": "registry.invalid/processor@sha256:" + "a" * 64,
                "pull_policy": "never",
                "restart": "no",
                "init": True,
                "user": "10002:10002",
                "read_only": True,
                "network_mode": "none",
                "ipc": "none",
                "pids_limit": 64,
                "cpus": 2.0,
                "mem_limit": "4g",
                "memswap_limit": "4g",
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "ulimits": {"nofile": {"soft": 1024, "hard": 1024}},
                "logging": {"driver": "none"},
                "environment": {
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "TACUA_PROCESSOR_MODEL_ID": "synthetic-model",
                },
                "tmpfs": [
                    "/tmp:rw,nosuid,nodev,noexec,size=268435456,uid=10002,gid=10002,mode=0700",
                ],
                "entrypoint": ["/opt/tacua/processor"],
                "command": [
                    "--input",
                    PROFILE.INPUT_TARGET,
                    "--model",
                    PROFILE.MODEL_TARGET,
                ],
                "labels": {
                    "com.tacua.private-pilot-processor": "true",
                    "com.tacua.runner-contract": RUNNER.COMMAND_CONTRACT,
                    "com.tacua.runner-role": RUNNER.PROCESSOR_ROLE,
                    "com.tacua.max-container-runtime-seconds": "150",
                    "com.tacua.max-runner-seconds": "210",
                },
            }
        }
    }


def stale_container_metadata(
    instance: str,
    staging: Path,
    container_id: str,
    *,
    role: str = RUNNER.PROCESSOR_ROLE,
) -> dict:
    volume_name = f"tacua-private-payload-{instance}"
    payload_root = f"/tacua-private-{instance}"
    read_only = role == RUNNER.PROCESSOR_ROLE
    name_prefix = "tacua-private-processor-" if read_only else "tacua-private-carrier-"
    entrypoint = "/opt/tacua/processor" if read_only else RUNNER.CARRIER_ENTRYPOINT_PREFIX + instance
    command = (
        ["--input", f"{payload_root}/input/input.json", "--model", f"{payload_root}/model/model"]
        if read_only
        else [RUNNER.CARRIER_COMMAND_PREFIX + instance]
    )
    environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": RUNNER.PROCESSOR_PATH}
    if read_only:
        environment["TACUA_PROCESSOR_MODEL_ID"] = "synthetic-model"
    labels = {
        RUNNER.PRIVATE_LABEL: "true",
        RUNNER.CONTRACT_LABEL: RUNNER.COMMAND_CONTRACT,
        RUNNER.INSTANCE_LABEL: instance,
        RUNNER.STAGING_LABEL: staging.name,
        RUNNER.ROLE_LABEL: role,
        RUNNER.VOLUME_LABEL: volume_name,
        RUNNER.CONFIG_DIGEST_LABEL: RUNNER._runtime_config_digest(
            command=command,
            entrypoint=entrypoint,
            environment=environment,
        ),
        RUNNER.CONTAINER_RUNTIME_LABEL: str(RUNNER.MAX_CONTAINER_RUNTIME_SECONDS),
        RUNNER.RUNNER_RUNTIME_LABEL: str(RUNNER.RUNNER_HARD_BUDGET_SECONDS),
    }
    if read_only:
        labels[RUNNER.MODEL_ID_LABEL] = "synthetic-model"
    return {
        "Id": container_id,
        "Name": "/" + name_prefix + instance,
        "State": {
            "Running": False,
            "Status": "exited" if read_only else "created",
            "StartedAt": "2026-07-22T00:00:00Z" if read_only else "0001-01-01T00:00:00Z",
        },
        "RestartCount": 0,
        "Config": {
            "Image": "sha256:" + "a" * 64,
            "Entrypoint": [entrypoint],
            "Cmd": command,
            "Env": [f"{key}={value}" for key, value in environment.items()],
            "User": f"{RUNNER.PROCESSOR_UID}:{RUNNER.PROCESSOR_GID}",
            "WorkingDir": "/",
            "StopSignal": "SIGKILL",
            "Healthcheck": {"Test": ["NONE"]},
            "Volumes": None,
            "ExposedPorts": None,
            "Labels": labels,
        },
        "HostConfig": {
            "NetworkMode": "none",
            "IpcMode": "none",
            "ReadonlyRootfs": read_only,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 64,
            "NanoCpus": 2_000_000_000,
            "Memory": 4_294_967_296,
            "MemorySwap": 4_294_967_296,
            "Ulimits": [{"Name": "nofile", "Hard": 1024, "Soft": 1024}],
            "LogConfig": {"Type": "none", "Config": {}},
            "Init": True,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "AutoRemove": False,
            "PortBindings": {},
            "PublishAllPorts": False,
            "Devices": [],
            "DeviceRequests": None,
            "GroupAdd": None,
            "PidMode": "",
            "UTSMode": "",
            "UsernsMode": "",
            "Binds": None,
            "Mounts": [
                {
                    "Type": "volume",
                    "Source": volume_name,
                    "Target": payload_root,
                    "ReadOnly": read_only,
                    "VolumeOptions": {"NoCopy": True},
                }
            ],
            "Tmpfs": (
                {
                    "/tmp": "rw,nosuid,nodev,noexec,size=268435456,uid=10002,gid=10002,mode=0700",
                }
                if read_only
                else None
            ),
        },
        "NetworkSettings": {"Networks": {"none": {"Gateway": "", "IPAddress": "", "IPPrefixLen": 0, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": ""}}},
        "Mounts": [
            {
                "Type": "volume",
                "Name": volume_name,
                "Destination": payload_root,
                "Driver": "local",
                "RW": not read_only,
            }
        ],
    }


def stale_volume_metadata(instance: str, staging: Path) -> dict:
    volume_name = f"tacua-private-payload-{instance}"
    return {
        "Name": volume_name,
        "Driver": "local",
        "Scope": "local",
        "Options": None,
        "Labels": {
            RUNNER.PRIVATE_LABEL: "true",
            RUNNER.CONTRACT_LABEL: RUNNER.COMMAND_CONTRACT,
            RUNNER.INSTANCE_LABEL: instance,
            RUNNER.STAGING_LABEL: staging.name,
            RUNNER.VOLUME_LABEL: volume_name,
        },
    }


class IsolatedProcessorTests(unittest.TestCase):
    def test_overlapping_runner_fails_busy_before_stale_reaping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock_path = root / "runner.lock"
            output = root / "output"
            output.mkdir()
            child_source = """
import importlib.util
from pathlib import Path
import sys

specification = importlib.util.spec_from_file_location("tacua_lock_holder", Path(sys.argv[1]))
module = importlib.util.module_from_spec(specification)
specification.loader.exec_module(module)
module.RUNNER_LOCK_PATH = Path(sys.argv[2])
descriptor = module._acquire_runner_lock()
print("locked", flush=True)
sys.stdin.buffer.read(1)
module._release_runner_lock(descriptor)
"""
            holder = subprocess.Popen(
                [sys.executable, "-B", "-c", child_source, str(RUNNER_PATH), str(lock_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                assert holder.stdout is not None
                ready, _writable, _exceptional = select.select([holder.stdout], [], [], 10)
                if not ready:
                    holder.kill()
                    _stdout, stderr = holder.communicate()
                    self.fail(f"lock holder did not become ready: {stderr!r}")
                self.assertEqual(b"locked\n", holder.stdout.readline())
                with mock.patch.object(RUNNER, "RUNNER_LOCK_PATH", lock_path), mock.patch.object(
                    RUNNER,
                    "_reap_stale_containers",
                ) as reaper:
                    with self.assertRaises(RUNNER.IsolationError) as raised:
                        RUNNER.run({}, root / "unused-input", output)
                self.assertEqual("PROCESSOR_RUNNER_BUSY", raised.exception.code)
                reaper.assert_not_called()
                self.assertEqual(0o600, lock_path.stat().st_mode & 0o777)
            finally:
                if holder.poll() is None:
                    assert holder.stdin is not None
                    try:
                        holder.stdin.write(b"x")
                        holder.stdin.flush()
                    except BrokenPipeError:
                        pass
                holder.communicate(timeout=10)

    def test_synthetic_integration_refuses_preexisting_labels_without_mutation(self) -> None:
        with mock.patch.object(
            INTEGRATION, "_fixture_container_ids", return_value=["a" * 64]
        ), mock.patch.object(
            INTEGRATION, "_fixture_volume_names", return_value=[]
        ), mock.patch.object(INTEGRATION, "_docker") as docker, mock.patch.object(
            INTEGRATION.RUNNER, "_reap_stale_containers"
        ) as reaper:
            with self.assertRaises(RuntimeError):
                INTEGRATION.main()
        docker.assert_not_called()
        reaper.assert_not_called()

    def test_runner_lock_rejects_nonprivate_mode_before_reaping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock_path = root / "runner.lock"
            lock_path.write_bytes(b"")
            lock_path.chmod(0o644)
            with mock.patch.object(RUNNER, "RUNNER_LOCK_PATH", lock_path), mock.patch.object(
                RUNNER,
                "_reap_stale_containers",
            ) as reaper:
                with self.assertRaises(RUNNER.IsolationError) as raised:
                    RUNNER.run({}, root / "unused-input", root)
            self.assertEqual("PROCESSOR_RUNNER_LOCK_INVALID", raised.exception.code)
            reaper.assert_not_called()

    def test_parent_container_and_whole_runner_deadlines_have_closed_margins(self) -> None:
        self.assertEqual(240, RUNNER.OUTER_ADAPTER_TIMEOUT_SECONDS)
        self.assertLess(RUNNER.MAX_CONTAINER_RUNTIME_SECONDS, RUNNER.RUNNER_WORK_BUDGET_SECONDS)
        self.assertLess(RUNNER.RUNNER_WORK_BUDGET_SECONDS, RUNNER.RUNNER_HARD_BUDGET_SECONDS)
        self.assertLess(RUNNER.RUNNER_HARD_BUDGET_SECONDS, RUNNER.OUTER_ADAPTER_TIMEOUT_SECONDS)
        self.assertEqual(
            30,
            RUNNER.OUTER_ADAPTER_TIMEOUT_SECONDS - RUNNER.RUNNER_HARD_BUDGET_SECONDS,
        )
        with mock.patch.dict(
            os.environ,
            {RUNNER.OUTER_TIMEOUT_ENV: str(RUNNER.OUTER_ADAPTER_TIMEOUT_SECONDS)},
        ):
            RUNNER.validate_outer_timeout_environment()
        with mock.patch.dict(os.environ, {RUNNER.OUTER_TIMEOUT_ENV: "210"}):
            with self.assertRaises(RUNNER.IsolationError) as raised:
                RUNNER.validate_outer_timeout_environment()
        self.assertEqual("INVALID_OUTER_ADAPTER_TIMEOUT", raised.exception.code)

    def test_each_docker_step_timeout_is_capped_by_the_remaining_runner_budget(self) -> None:
        completed = subprocess.CompletedProcess(["docker", "version"], 0, b"ok", b"")
        with mock.patch.object(RUNNER.time, "monotonic", return_value=100.0), mock.patch.object(
            RUNNER.subprocess,
            "run",
            return_value=completed,
        ) as invoked:
            RUNNER._run_checked(
                ["docker", "version"],
                deadline=105.0,
                maximum_timeout=30,
            )
        self.assertEqual(5.0, invoked.call_args.kwargs["timeout"])

    def test_attached_processor_stream_is_incrementally_bounded_and_reaped(self) -> None:
        real_popen = subprocess.Popen

        def launch(_argv, **kwargs):
            return real_popen(
                [sys.executable, "-c", "import sys,time;sys.stdout.buffer.write(b'123456789');sys.stdout.flush();time.sleep(2)"],
                **kwargs,
            )

        started = time.monotonic()
        with mock.patch.object(RUNNER.subprocess, "Popen", side_effect=launch), mock.patch.object(
            RUNNER, "MAX_OUTPUT_STREAM_BYTES", 8
        ), mock.patch.object(RUNNER, "_run_cleanup_command", return_value=True) as killed:
            with self.assertRaises(RUNNER.IsolationError) as raised:
                RUNNER._run_attached_processor(
                    "tacua-private-processor-test",
                    time.monotonic() + 2,
                    time.monotonic() + 3,
                )
        self.assertEqual("PROCESSOR_OUTPUT_LIMIT", raised.exception.code)
        self.assertLess(time.monotonic() - started, 2)
        killed.assert_called_once()

    def test_attached_processor_deadline_kills_without_pipe_deadlock(self) -> None:
        real_popen = subprocess.Popen

        def launch(_argv, **kwargs):
            return real_popen([sys.executable, "-c", "import time;time.sleep(30)"], **kwargs)

        started = time.monotonic()
        with mock.patch.object(RUNNER.subprocess, "Popen", side_effect=launch), mock.patch.object(
            RUNNER, "_run_cleanup_command", return_value=True
        ):
            with self.assertRaises(RUNNER.IsolationError) as raised:
                RUNNER._run_attached_processor(
                    "tacua-private-processor-test",
                    time.monotonic() + 0.05,
                    time.monotonic() + 2,
                )
        self.assertEqual("PROCESSOR_TIMEOUT", raised.exception.code)
        self.assertLess(time.monotonic() - started, 2)

    def test_command_requires_explicit_digest_pinned_image_model_and_exact_argv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model = root / "operator-model.bin"
            model.write_bytes(b"synthetic model fixture only")
            model_digest = "sha256:" + hashlib.sha256(model.read_bytes()).hexdigest()
            command = {
                "argv": [
                    "/opt/tacua/processor",
                    "--input",
                    RUNNER.INPUT_PLACEHOLDER,
                    "--model",
                    RUNNER.MODEL_PLACEHOLDER,
                ],
                "contract_version": RUNNER.COMMAND_CONTRACT,
                "image": "registry.invalid/processor@sha256:" + "a" * 64,
                "model_digest": model_digest,
                "model_id": "operator-model-v1",
                "model_path": str(model),
                "timeout_seconds": RUNNER.MAX_CONTAINER_RUNTIME_SECONDS,
            }
            command_path = root / "command.json"
            command_path.write_bytes(RUNNER.canonical_json(command))
            with self.assertRaises(RUNNER.IsolationError) as raised:
                RUNNER.load_command(command_path)
            self.assertEqual("INVALID_ISOLATION_COMMAND", raised.exception.code)
            command_path.chmod(0o600)
            loaded = RUNNER.load_command(command_path)
            instance = "12345-" + "a" * 24
            container_name = "tacua-private-processor-" + instance
            payload_root = "/tacua-private-" + instance
            staging_name = "tacua-isolated-input-" + instance + "-fixture"
            docker = RUNNER.build_docker_create(
                loaded,
                container_name,
                payload_root,
                staging_name,
            )
            rendered = "\n".join(docker)
            for required in (
                "--pull=never",
                "--no-healthcheck",
                "--network\nnone",
                "--ipc\nnone",
                "--init",
                "--read-only",
                "10002:10002",
                "no-new-privileges:true",
                "--pids-limit\n64",
                "--cpus\n2.0",
                "--memory\n4g",
                "--memory-swap\n4g",
                "--log-driver\nnone",
                payload_root + "/input/input.json",
                payload_root + "/model/model",
                "--entrypoint\n/opt/tacua/processor",
            ):
                self.assertIn(required, rendered)
            self.assertNotIn("docker.sock", rendered)
            self.assertNotIn(str(model), rendered)
            mount_index = docker.index("--mount")
            self.assertEqual(
                "type=volume,source=tacua-private-payload-12345-aaaaaaaaaaaaaaaaaaaaaaaa,"
                "target=/tacua-private-12345-aaaaaaaaaaaaaaaaaaaaaaaa,readonly,volume-nocopy",
                docker[mount_index + 1],
            )
            image_index = docker.index(command["image"])
            self.assertEqual(
                [
                    command["image"],
                    "--input",
                    payload_root + "/input/input.json",
                    "--model",
                    payload_root + "/model/model",
                ],
                docker[image_index:],
            )
            self.assertEqual(1, docker.count("/opt/tacua/processor"))

            carrier = RUNNER.build_payload_carrier_create(
                loaded,
                "tacua-private-carrier-" + instance,
                payload_root,
                staging_name,
            )
            carrier_mount = carrier[carrier.index("--mount") + 1]
            self.assertNotIn("readonly", carrier_mount)
            self.assertIn("volume-nocopy", carrier_mount)
            self.assertNotIn("--read-only", carrier)
            self.assertEqual(
                "/tacua-carrier-never-run-" + instance,
                carrier[carrier.index("--entrypoint") + 1],
            )

            mutable = copy.deepcopy(command)
            mutable["image"] = "registry.invalid/processor:latest"
            command_path.write_bytes(RUNNER.canonical_json(mutable))
            with self.assertRaises(RUNNER.IsolationError):
                RUNNER.load_command(command_path)

            too_long = copy.deepcopy(command)
            too_long["timeout_seconds"] = RUNNER.MAX_CONTAINER_RUNTIME_SECONDS + 1
            command_path.write_bytes(RUNNER.canonical_json(too_long))
            with self.assertRaises(RUNNER.IsolationError) as raised:
                RUNNER.load_command(command_path)
            self.assertEqual("INVALID_ISOLATION_COMMAND", raised.exception.code)

    def test_selected_image_cannot_add_environment_or_implicit_writable_volumes(self) -> None:
        RUNNER.validate_image_metadata(
            json.dumps([{"Config": {"Env": ["PATH=/usr/bin", "LANG=C.UTF-8"], "Healthcheck": None, "Volumes": None}}]).encode()
        )
        cases = [
            [{"Config": {"Env": ["PROVIDER_TOKEN=synthetic"], "Healthcheck": None, "Volumes": None}}],
            [{"Config": {"Env": [], "Healthcheck": None, "Volumes": {"/model-cache": {}}}}],
            [{"Config": {"Env": [], "Healthcheck": {"Test": ["CMD", "/image-health"]}, "Volumes": None}}],
        ]
        for metadata in cases:
            with self.subTest(metadata=metadata):
                with self.assertRaises(RUNNER.IsolationError):
                    RUNNER.validate_image_metadata(json.dumps(metadata).encode())

    def test_command_file_is_symlink_safe_and_uses_the_strict_tacua_json_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model = root / "model.bin"
            model.write_bytes(b"synthetic model")
            command = isolated_command(model)
            target = root / "command-target.json"
            target.write_bytes(RUNNER.canonical_json(command))
            target.chmod(0o600)
            link = root / "command-link.json"
            link.symlink_to(target)
            with self.assertRaises(RUNNER.IsolationError) as raised:
                RUNNER.load_command(link)
            self.assertEqual("INVALID_ISOLATION_COMMAND", raised.exception.code)

            malformed: list[bytes] = []
            floating = copy.deepcopy(command)
            floating["timeout_seconds"] = 1.0
            malformed.append(json.dumps(floating, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode())
            unsafe = copy.deepcopy(command)
            unsafe["timeout_seconds"] = RUNNER.MAX_SAFE_JSON_INTEGER + 1
            malformed.append(json.dumps(unsafe, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode())
            non_nfc = copy.deepcopy(command)
            non_nfc["model_id"] = "e\u0301"
            malformed.append(json.dumps(non_nfc, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode())
            finite_overflow = RUNNER.canonical_json(command).replace(b'"timeout_seconds":30', b'"timeout_seconds":1e309')
            malformed.append(finite_overflow)
            deeply_nested = b"[" * 70 + b"null" + b"]" * 70
            malformed.append(deeply_nested)
            for index, payload in enumerate(malformed):
                path = root / f"malformed-{index}.json"
                path.write_bytes(payload)
                path.chmod(0o600)
                with self.subTest(index=index):
                    with self.assertRaises(RUNNER.IsolationError) as failure:
                        RUNNER.load_command(path)
                    self.assertEqual("INVALID_ISOLATION_COMMAND", failure.exception.code)

    def test_nonfinite_command_cli_failure_is_content_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model = root / "model.bin"
            model.write_bytes(b"synthetic model")
            payload = RUNNER.canonical_json(isolated_command(model)).replace(
                b'"timeout_seconds":30', b'"timeout_seconds":1e309'
            )
            command_path = root / "command.json"
            command_path.write_bytes(payload)
            command_path.chmod(0o600)
            output = root / "output"
            output.mkdir()
            environment = dict(os.environ)
            environment[RUNNER.OUTER_TIMEOUT_ENV] = str(RUNNER.OUTER_ADAPTER_TIMEOUT_SECONDS)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(RUNNER_PATH),
                    "--command-file",
                    str(command_path),
                    "--input",
                    str(root / "unused-input"),
                    "--output-directory",
                    str(output),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=10,
                check=False,
            )
            self.assertEqual(1, completed.returncode)
            self.assertEqual(b"", completed.stdout)
            self.assertEqual(b"INVALID_ISOLATION_COMMAND\n", completed.stderr)
            self.assertNotIn(b"Traceback", completed.stderr)

    def test_selected_model_is_rehashed_into_a_nonroot_readable_immutable_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "operator-model.bin"
            destination = root / "isolated-model.bin"
            source.write_bytes(b"synthetic model")
            source.chmod(0o600)
            digest = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
            RUNNER._copy_selected_model(source, destination, digest)
            self.assertEqual(source.read_bytes(), destination.read_bytes())
            self.assertEqual(0o444, destination.stat().st_mode & 0o777)
            with self.assertRaises(RUNNER.IsolationError):
                RUNNER._copy_selected_model(source, root / "wrong-copy.bin", "sha256:" + "0" * 64)

    def test_source_descriptors_are_copied_into_a_bounded_read_only_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.bin"
            evidence.write_bytes(b"synthetic evidence")
            descriptor = os.open(evidence, os.O_RDONLY)
            try:
                source = sealed_input(f"/dev/fd/{descriptor}")
                source_path = root / "source.json"
                source_path.write_bytes(RUNNER.canonical_json(source))
                input_directory = root / "bundle"
                input_directory.mkdir()
                output = input_directory / "input.json"
                result_contract = RUNNER.prepare_input(source_path, output)
                wrapper = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(RUNNER.SOURCE_RESULT_CONTRACT, result_contract)
                self.assertEqual(RUNNER.INPUT_CONTRACT, wrapper["contract_version"])
                self.assertEqual(source["input_digest"], wrapper["source_input_digest"])
                rewritten = wrapper["source_input"]["capture"]["segments"][0]["read_only_path"]
                self.assertEqual("/run/tacua-input/evidence/evidence-000000.bin", rewritten)
                self.assertNotIn("stage_inputs", wrapper["source_input"])
                expected_source = copy.deepcopy(source)
                expected_source["capture"]["segments"][0]["read_only_path"] = rewritten
                expected_wrapper = {
                    "contract_version": RUNNER.INPUT_CONTRACT,
                    "isolated_input_digest": "sha256:" + "0" * 64,
                    "source_input": expected_source,
                    "source_input_digest": source["input_digest"],
                }
                digest_subject = copy.deepcopy(expected_wrapper)
                digest_subject.pop("isolated_input_digest")
                expected_wrapper["isolated_input_digest"] = "sha256:" + hashlib.sha256(
                    RUNNER.canonical_json(digest_subject)
                ).hexdigest()
                self.assertEqual(RUNNER.canonical_json(expected_wrapper), output.read_bytes())
                self.assertEqual(b"synthetic evidence", (input_directory / "evidence" / "evidence-000000.bin").read_bytes())
                self.assertEqual(0o444, output.stat().st_mode & 0o777)
                self.assertEqual(
                    0o444,
                    (input_directory / "evidence" / "evidence-000000.bin").stat().st_mode & 0o777,
                )
                (input_directory / "evidence").chmod(0o700)
            finally:
                os.close(descriptor)

    def test_v11_stage_artifact_is_preserved_and_both_digests_bind_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.bin"
            evidence.write_bytes(b"synthetic evidence")
            descriptor = os.open(evidence, os.O_RDONLY)
            bundle = root / "bundle"
            bundle.mkdir()
            try:
                source = sealed_input_v11(f"/dev/fd/{descriptor}")
                source_path = root / "source.json"
                source_path.write_bytes(RUNNER.canonical_json(source))
                output = bundle / "input.json"
                result_contract = RUNNER.prepare_input(source_path, output)

                self.assertEqual(RUNNER.SOURCE_RESULT_CONTRACT_V11, result_contract)
                wrapper = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(
                    {
                        "contract_version",
                        "isolated_input_digest",
                        "source_input",
                        "source_input_digest",
                    },
                    set(wrapper),
                )
                self.assertEqual(RUNNER.INPUT_CONTRACT, wrapper["contract_version"])
                self.assertEqual(source["input_digest"], wrapper["source_input_digest"])
                self.assertEqual(
                    source["stage_inputs"], wrapper["source_input"]["stage_inputs"]
                )
                self.assertIn(
                    "PRIVATE_ISOLATED_TRANSCRIPT_SENTINEL",
                    RUNNER.canonical_json(wrapper["source_input"]["stage_inputs"]).decode(),
                )
                expected_source = copy.deepcopy(source)
                expected_source["capture"]["segments"][0]["read_only_path"] = (
                    "/run/tacua-input/evidence/evidence-000000.bin"
                )
                self.assertEqual(expected_source, wrapper["source_input"])
                digest_subject = copy.deepcopy(wrapper)
                isolated_digest = digest_subject.pop("isolated_input_digest")
                self.assertEqual(
                    "sha256:" + hashlib.sha256(
                        RUNNER.canonical_json(digest_subject)
                    ).hexdigest(),
                    isolated_digest,
                )
                self.assertEqual(RUNNER.canonical_json(wrapper), output.read_bytes())

                os.lseek(descriptor, 0, os.SEEK_SET)
                transcribe_source = sealed_input_v11(
                    f"/dev/fd/{descriptor}", stage_name="transcribe"
                )
                transcribe_path = root / "transcribe-source.json"
                transcribe_path.write_bytes(
                    RUNNER.canonical_json(transcribe_source)
                )
                transcribe_bundle = root / "transcribe-bundle"
                transcribe_bundle.mkdir()
                self.assertEqual(
                    RUNNER.SOURCE_RESULT_CONTRACT_V11,
                    RUNNER.prepare_input(
                        transcribe_path, transcribe_bundle / "input.json"
                    ),
                )
                transcribe_wrapper = json.loads(
                    (transcribe_bundle / "input.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    {"artifacts": []},
                    transcribe_wrapper["source_input"]["stage_inputs"],
                )
            finally:
                if (bundle / "evidence").exists():
                    (bundle / "evidence").chmod(0o700)
                transcribe_evidence = root / "transcribe-bundle" / "evidence"
                if transcribe_evidence.exists():
                    transcribe_evidence.chmod(0o700)
                os.close(descriptor)

    def test_source_contracts_reject_cross_version_stage_inputs_and_tampering(self) -> None:
        legacy_with_artifacts = sealed_input("/dev/fd/0")
        legacy_with_artifacts["stage_inputs"] = {"artifacts": []}
        reseal_source_input(legacy_with_artifacts)

        align_without_artifact = sealed_input_v11("/dev/fd/0")
        align_without_artifact["stage_inputs"]["artifacts"] = []
        reseal_source_input(align_without_artifact)

        transcribe_with_artifact = sealed_input_v11("/dev/fd/0")
        transcribe_with_artifact["binding"]["stage_name"] = "transcribe"
        reseal_source_input(transcribe_with_artifact)

        extra_stage_input_field = sealed_input_v11("/dev/fd/0")
        extra_stage_input_field["stage_inputs"]["unexpected"] = []
        reseal_source_input(extra_stage_input_field)

        wrong_artifact_digest = sealed_input_v11(
            "/dev/fd/0", transcript_text="PRIVATE_TAMPER_SENTINEL"
        )
        wrong_artifact_digest["stage_inputs"]["artifacts"][0]["payload"]["spans"][0][
            "text"
        ] = "PRIVATE_CHANGED_SENTINEL"
        reseal_source_input(wrong_artifact_digest)

        wrong_source_binding = sealed_input_v11("/dev/fd/0")
        artifact = wrong_source_binding["stage_inputs"]["artifacts"][0]
        artifact["payload"]["source_segments"][0]["content_digest"] = (
            "sha256:" + "0" * 64
        )
        reseal_stage_artifact(artifact)
        reseal_source_input(wrong_source_binding)

        nul_transcript_text = sealed_input_v11("/dev/fd/0")
        artifact = nul_transcript_text["stage_inputs"]["artifacts"][0]
        artifact["payload"]["spans"][0]["text"] = "private\x00text"
        reseal_stage_artifact(artifact)
        reseal_source_input(nul_transcript_text)

        fixture_only_stage_key = sealed_input_v11("/dev/fd/0")
        transcribe_stage = fixture_only_stage_key["job"]["pipeline"]["stages"][0]
        transcribe_stage["stage_name"] = transcribe_stage.pop("name")
        reseal_source_input(fixture_only_stage_key)

        for index, invalid in enumerate(
            (
                legacy_with_artifacts,
                align_without_artifact,
                transcribe_with_artifact,
                extra_stage_input_field,
                wrong_artifact_digest,
                wrong_source_binding,
                nul_transcript_text,
                fixture_only_stage_key,
            )
        ):
            with tempfile.TemporaryDirectory() as directory, self.subTest(index=index):
                root = Path(directory)
                source_path = root / "source.json"
                source_path.write_bytes(RUNNER.canonical_json(invalid))
                bundle = root / "bundle"
                bundle.mkdir()
                with self.assertRaises(RUNNER.IsolationError) as raised:
                    RUNNER.prepare_input(source_path, bundle / "input.json")
                self.assertEqual("INVALID_PROCESSING_INPUT", raised.exception.code)
                self.assertNotIn("PRIVATE_", str(raised.exception))

    def test_v11_artifact_and_source_input_byte_limits_fail_before_copy(self) -> None:
        source = sealed_input_v11(
            "/dev/fd/0", transcript_text="PRIVATE_OVERSIZE_SENTINEL"
        )
        source_bytes = RUNNER.canonical_json(source)
        artifact_bytes = RUNNER.canonical_json(
            source["stage_inputs"]["artifacts"][0]
        )
        limits = (
            ("MAX_PROCESSING_ARTIFACT_BYTES", len(artifact_bytes) - 1),
            ("MAX_INPUT_BYTES", len(source_bytes) - 1),
        )
        for name, maximum in limits:
            with tempfile.TemporaryDirectory() as directory, self.subTest(name=name):
                root = Path(directory)
                source_path = root / "source.json"
                source_path.write_bytes(source_bytes)
                bundle = root / "bundle"
                bundle.mkdir()
                with mock.patch.object(RUNNER, name, maximum):
                    with self.assertRaises(RUNNER.IsolationError) as raised:
                        RUNNER.prepare_input(source_path, bundle / "input.json")
                self.assertEqual("INVALID_PROCESSING_INPUT", raised.exception.code)
                self.assertNotIn("PRIVATE_OVERSIZE_SENTINEL", str(raised.exception))
                self.assertEqual([], list(bundle.iterdir()))

    def test_processing_input_rejects_float_unsafe_integer_non_nfc_and_deep_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = sealed_input("/dev/fd/0")
            cases: list[bytes] = []
            floating = copy.deepcopy(source)
            floating["binding"]["attempt"] = 1.0
            cases.append(json.dumps(floating, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode())
            unsafe = copy.deepcopy(source)
            unsafe["binding"]["attempt"] = RUNNER.MAX_SAFE_JSON_INTEGER + 1
            cases.append(json.dumps(unsafe, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode())
            non_nfc = copy.deepcopy(source)
            non_nfc["binding"]["job_id"] = "job-e\u0301"
            cases.append(json.dumps(non_nfc, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode())
            cases.append(b"[" * 70 + b"null" + b"]" * 70)
            for index, payload in enumerate(cases):
                source_path = root / f"source-{index}.json"
                source_path.write_bytes(payload)
                bundle = root / f"bundle-{index}"
                bundle.mkdir()
                with self.subTest(index=index):
                    with self.assertRaises(RUNNER.IsolationError) as raised:
                        RUNNER.prepare_input(source_path, bundle / "input.json")
                    self.assertEqual("INVALID_PROCESSING_INPUT", raised.exception.code)

    def test_evidence_copy_is_rehashed_against_each_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.bin"
            evidence.write_bytes(b"synthetic evidence")
            descriptor = os.open(evidence, os.O_RDONLY)
            try:
                source = sealed_input(f"/dev/fd/{descriptor}")
                source["capture"]["segments"][0]["content_digest"] = "sha256:" + "0" * 64
                subject = copy.deepcopy(source)
                subject.pop("input_digest")
                source["input_digest"] = "sha256:" + hashlib.sha256(
                    RUNNER.canonical_json(subject)
                ).hexdigest()
                source_path = root / "source.json"
                source_path.write_bytes(RUNNER.canonical_json(source))
                bundle = root / "bundle"
                bundle.mkdir()
                with self.assertRaises(RUNNER.IsolationError) as raised:
                    RUNNER.prepare_input(source_path, bundle / "input.json")
                self.assertEqual("EVIDENCE_DIGEST_MISMATCH", raised.exception.code)
                (bundle / "evidence").chmod(0o700)
            finally:
                os.close(descriptor)

    def test_private_staging_is_copied_before_start_and_never_host_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model = root / "model.bin"
            evidence = root / "evidence.bin"
            output = root / "output"
            model.write_bytes(b"synthetic model")
            evidence.write_bytes(b"synthetic evidence")
            output.mkdir()
            descriptor = os.open(evidence, os.O_RDONLY)
            commands: list[list[str]] = []
            command_options: list[dict] = []
            cleanup_commands: list[list[str]] = []
            labeled_staging: Path | None = None
            try:
                source_path = root / "input.json"
                source_path.write_bytes(
                    RUNNER.canonical_json(
                        sealed_input_v11(f"/dev/fd/{descriptor}")
                    )
                )
                command = {
                    "argv": [
                        "/opt/tacua/processor",
                        "--input",
                        RUNNER.INPUT_PLACEHOLDER,
                        "--model",
                        RUNNER.MODEL_PLACEHOLDER,
                    ],
                    "contract_version": RUNNER.COMMAND_CONTRACT,
                    "image": "sha256:" + "a" * 64,
                    "model_digest": "sha256:" + hashlib.sha256(model.read_bytes()).hexdigest(),
                    "model_id": "synthetic-model",
                    "model_path": str(model),
                    "timeout_seconds": 30,
                }

                def fake_run(argv, **kwargs):
                    nonlocal labeled_staging
                    commands.append(list(argv))
                    command_options.append(dict(kwargs))
                    if argv[:3] == ["docker", "image", "inspect"]:
                        payload = [{"Config": {"Env": [], "Healthcheck": None, "Volumes": None}}]
                        return subprocess.CompletedProcess(argv, 0, json.dumps(payload).encode(), b"")
                    if argv[:3] == ["docker", "volume", "create"]:
                        return subprocess.CompletedProcess(argv, 0, (argv[-1] + "\n").encode(), b"")
                    if argv[:2] == ["docker", "create"]:
                        self.assertTrue(any(RUNNER.PRIVATE_LABEL in argument for argument in argv))
                        mount = argv[argv.index("--mount") + 1]
                        self.assertNotIn(str(root), mount)
                        role = next(
                            argv[index + 1].split("=", 1)[1]
                            for index, argument in enumerate(argv[:-1])
                            if argument == "--label" and argv[index + 1].startswith(RUNNER.ROLE_LABEL + "=")
                        )
                        if role == RUNNER.PROCESSOR_ROLE:
                            self.assertIn("--read-only", argv)
                            self.assertIn("readonly", mount)
                        else:
                            self.assertEqual(RUNNER.CARRIER_ROLE, role)
                            self.assertNotIn("--read-only", argv)
                            self.assertNotIn("readonly", mount)
                        staging_label = next(
                            argv[index + 1]
                            for index, argument in enumerate(argv[:-1])
                            if argument == "--label" and argv[index + 1].startswith(RUNNER.STAGING_LABEL + "=")
                        )
                        labeled_staging = Path(tempfile.gettempdir()) / staging_label.split("=", 1)[1]
                        self.assertEqual(0o700, labeled_staging.stat().st_mode & 0o777)
                        self.assertEqual([], list(labeled_staging.iterdir()))
                        identifier = ("d" if role == RUNNER.CARRIER_ROLE else "e") * 64
                        return subprocess.CompletedProcess(argv, 0, (identifier + "\n").encode(), b"")
                    if argv[:2] == ["docker", "cp"] and ":" in argv[3]:
                        payload = Path(argv[2])
                        staging = payload.parent
                        self.assertIn("tacua-private-carrier-", argv[3])
                        self.assertEqual(0o700, staging.stat().st_mode & 0o777)
                        self.assertEqual(0o555, payload.stat().st_mode & 0o777)
                        self.assertEqual(0o555, (payload / "input").stat().st_mode & 0o777)
                        self.assertEqual(0o444, (payload / "input" / "input.json").stat().st_mode & 0o777)
                        self.assertEqual(0o444, (payload / "model" / "model").stat().st_mode & 0o777)
                    if argv[:2] == ["docker", "wait"]:
                        return subprocess.CompletedProcess(argv, 0, b"0\n", b"")
                    return subprocess.CompletedProcess(argv, 0, b"", b"")

                def fake_attached(container_name, deadline, cleanup_deadline):
                    commands.append(["docker", "start", "--attach", container_name])
                    command_options.append({"deadline": deadline, "cleanup_deadline": cleanup_deadline})
                    return output_envelope(
                        {
                            "contract_version": RUNNER.SOURCE_RESULT_CONTRACT_V11,
                            "disposition": "checkpoint",
                        }
                    ), 0, False

                def fake_cleanup(argv, _deadline):
                    cleanup_commands.append(list(argv))
                    if argv[:4] == ["docker", "container", "rm", "--force"]:
                        assert labeled_staging is not None
                        self.assertFalse(labeled_staging.exists())
                    return True

                with mock.patch.object(RUNNER, "validate_runtime_environment"), mock.patch.object(
                    RUNNER, "_reap_stale_containers"
                ), mock.patch.object(
                    RUNNER,
                    "_run_checked",
                    side_effect=fake_run,
                ), mock.patch.object(
                    RUNNER,
                    "_run_cleanup_command",
                    side_effect=fake_cleanup,
                ), mock.patch.object(
                    RUNNER,
                    "_cleanup_container_running",
                    return_value=False,
                ), mock.patch.object(
                    RUNNER, "_validate_created_container_artifact"
                ) as artifact_validator, mock.patch.object(
                    RUNNER, "_run_attached_processor", side_effect=fake_attached
                ), mock.patch.object(
                    RUNNER, "_validate_completed_processor"
                ), mock.patch.object(RUNNER.os, "urandom", return_value=b"a" * 12):
                    result = RUNNER.run(command, source_path, output)
                self.assertEqual(
                    RUNNER.canonical_json(
                        {
                            "contract_version": RUNNER.SOURCE_RESULT_CONTRACT_V11,
                            "disposition": "checkpoint",
                        }
                    ),
                    result,
                )
                payload_copy_index = next(
                    index
                    for index, argv in enumerate(commands)
                    if argv[:2] == ["docker", "cp"] and ":" in argv[3]
                )
                start_index = next(index for index, argv in enumerate(commands) if argv[:2] == ["docker", "start"])
                carrier_remove_index = next(
                    index
                    for index, argv in enumerate(commands)
                    if argv[:4] == ["docker", "container", "rm", "--force"]
                    and "tacua-private-carrier-" in argv[4]
                )
                self.assertLess(payload_copy_index, start_index)
                self.assertLess(carrier_remove_index, start_index)
                self.assertEqual(3, artifact_validator.call_count)
                self.assertEqual(
                    [RUNNER.CARRIER_ROLE, RUNNER.PROCESSOR_ROLE, RUNNER.CARRIER_ROLE],
                    [call.args[1] for call in artifact_validator.call_args_list],
                )
                wait_index = next(index for index, argv in enumerate(commands) if argv[:2] == ["docker", "wait"])
                self.assertEqual(command_options[start_index]["deadline"], command_options[wait_index]["deadline"])
                self.assertLessEqual(command_options[start_index]["deadline"] - time.monotonic(), 30)
                self.assertTrue(any(argv[:4] == ["docker", "container", "rm", "--force"] for argv in cleanup_commands))
                self.assertEqual(["docker", "volume", "rm"], cleanup_commands[-1][:3])
            finally:
                os.close(descriptor)

    def test_v11_sensitive_population_failure_removes_artifact_staging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            evidence = root / "evidence.bin"
            evidence.write_bytes(b"synthetic evidence")
            descriptor = os.open(evidence, os.O_RDONLY)
            self.addCleanup(os.close, descriptor)
            source_path = root / "input.json"
            source_path.write_bytes(
                RUNNER.canonical_json(sealed_input_v11(f"/dev/fd/{descriptor}"))
            )
            command = {
                "argv": [
                    "/opt/tacua/processor",
                    "--input",
                    RUNNER.INPUT_PLACEHOLDER,
                    "--model",
                    RUNNER.MODEL_PLACEHOLDER,
                ],
                "contract_version": RUNNER.COMMAND_CONTRACT,
                "image": "sha256:" + "a" * 64,
                "model_digest": "sha256:" + "b" * 64,
                "model_id": "synthetic-model",
                "model_path": str(root / "unused-model"),
                "timeout_seconds": 30,
            }
            staging: Path | None = None
            calls: list[list[str]] = []

            def fake_run(argv, **_kwargs):
                nonlocal staging
                calls.append(list(argv))
                if argv[:3] == ["docker", "image", "inspect"]:
                    payload = [{"Config": {"Env": [], "Healthcheck": None, "Volumes": None}}]
                    return subprocess.CompletedProcess(argv, 0, json.dumps(payload).encode(), b"")
                if argv[:3] == ["docker", "volume", "create"]:
                    return subprocess.CompletedProcess(argv, 0, (argv[-1] + "\n").encode(), b"")
                if argv[:2] == ["docker", "create"]:
                    staging_label = next(
                        argv[index + 1]
                        for index, argument in enumerate(argv[:-1])
                        if argument == "--label" and argv[index + 1].startswith(RUNNER.STAGING_LABEL + "=")
                    )
                    staging = Path(tempfile.gettempdir()) / staging_label.split("=", 1)[1]
                    self.assertEqual([], list(staging.iterdir()))
                    role = next(
                        argv[index + 1].split("=", 1)[1]
                        for index, argument in enumerate(argv[:-1])
                        if argument == "--label" and argv[index + 1].startswith(RUNNER.ROLE_LABEL + "=")
                    )
                    identifier = ("4" if role == RUNNER.CARRIER_ROLE else "5") * 64
                    return subprocess.CompletedProcess(argv, 0, (identifier + "\n").encode(), b"")
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            cleanup_calls: list[list[str]] = []

            def fake_cleanup(argv, _deadline):
                cleanup_calls.append(list(argv))
                if argv[:4] == ["docker", "container", "rm", "--force"]:
                    assert staging is not None
                    self.assertFalse(staging.exists())
                return True

            def fail_model_copy(*_args, **_kwargs):
                assert staging is not None
                isolated_input = staging / "payload" / "input" / "input.json"
                self.assertIn(
                    b"PRIVATE_ISOLATED_TRANSCRIPT_SENTINEL",
                    isolated_input.read_bytes(),
                )
                raise RUNNER.IsolationError(
                    "COPY_PHASE_FAILED", "synthetic model copy failure"
                )

            with mock.patch.object(RUNNER, "validate_runtime_environment"), mock.patch.object(
                RUNNER, "_reap_stale_containers"
            ), mock.patch.object(
                RUNNER,
                "_run_checked",
                side_effect=fake_run,
            ), mock.patch.object(
                RUNNER,
                "_copy_selected_model",
                side_effect=fail_model_copy,
            ), mock.patch.object(
                RUNNER,
                "_cleanup_container_running",
                return_value=False,
            ), mock.patch.object(
                RUNNER,
                "_validate_created_container_artifact",
            ), mock.patch.object(
                RUNNER,
                "_run_cleanup_command",
                side_effect=fake_cleanup,
            ), mock.patch.object(RUNNER.os, "urandom", return_value=b"c" * 12):
                with self.assertRaises(RUNNER.IsolationError) as raised:
                    RUNNER.run(command, source_path, output)
            self.assertEqual("COPY_PHASE_FAILED", raised.exception.code)
            assert staging is not None
            self.assertFalse(staging.exists())
            self.assertEqual(["docker", "image", "inspect"], calls[0][:3])
            self.assertEqual(["docker", "volume", "create"], calls[1][:3])
            self.assertEqual(["docker", "create"], calls[2][:2])
            self.assertEqual(["docker", "create"], calls[3][:2])
            self.assertTrue(
                any(argv[:4] == ["docker", "container", "rm", "--force"] for argv in cleanup_calls)
            )
            self.assertEqual(["docker", "volume", "rm"], cleanup_calls[-1][:3])

    def test_next_authorized_run_reaps_carrier_processor_and_volume_in_order(self) -> None:
        instance = "54321-" + "b" * 24
        staging = Path(tempfile.mkdtemp(prefix=f"tacua-isolated-input-{instance}-"))
        staging.chmod(0o700)
        (staging / "input").mkdir()
        carrier_id = "b" * 64
        processor_id = "c" * 64
        volume_name = f"tacua-private-payload-{instance}"
        metadata = [
            stale_container_metadata(instance, staging, carrier_id, role=RUNNER.CARRIER_ROLE),
            stale_container_metadata(instance, staging, processor_id),
        ]
        volume_metadata = stale_volume_metadata(instance, staging)
        responses = [
            subprocess.CompletedProcess([], 0, f"{carrier_id}\n{processor_id}\n".encode(), b""),
            subprocess.CompletedProcess([], 0, (volume_name + "\n").encode(), b""),
            subprocess.CompletedProcess([], 0, json.dumps(metadata).encode(), b""),
            subprocess.CompletedProcess([], 0, json.dumps([volume_metadata]).encode(), b""),
            subprocess.CompletedProcess([], 0, b"false\n", b""),
            subprocess.CompletedProcess([], 0, b"false\n", b""),
            subprocess.CompletedProcess([], 0, b"false\n", b""),
            subprocess.CompletedProcess([], 0, b"false\n", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
        ]
        calls: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            calls.append(list(argv))
            return responses.pop(0)

        try:
            with mock.patch.object(RUNNER, "_run_checked", side_effect=fake_run):
                RUNNER._reap_stale_containers(time.monotonic() + 30)
            self.assertFalse(staging.exists())
            carrier_remove = calls.index(["docker", "container", "rm", "--force", carrier_id])
            processor_remove = calls.index(["docker", "container", "rm", "--force", processor_id])
            volume_remove = calls.index(["docker", "volume", "rm", volume_name])
            self.assertLess(carrier_remove, processor_remove)
            self.assertLess(processor_remove, volume_remove)
        finally:
            if staging.exists():
                RUNNER._remove_staging_root(staging)

    def test_stale_reaper_retains_all_recovery_identity_when_staging_removal_fails(self) -> None:
        instance = "54321-" + "d" * 24
        staging = Path(tempfile.mkdtemp(prefix=f"tacua-isolated-input-{instance}-"))
        staging.chmod(0o700)
        (staging / "sensitive-fixture").write_bytes(b"synthetic")
        container_id = "e" * 64
        volume_name = f"tacua-private-payload-{instance}"
        metadata = stale_container_metadata(instance, staging, container_id)
        volume_metadata = stale_volume_metadata(instance, staging)
        responses = [
            subprocess.CompletedProcess([], 0, (container_id + "\n").encode(), b""),
            subprocess.CompletedProcess([], 0, (volume_name + "\n").encode(), b""),
            subprocess.CompletedProcess([], 0, json.dumps([metadata]).encode(), b""),
            subprocess.CompletedProcess([], 0, json.dumps([volume_metadata]).encode(), b""),
            subprocess.CompletedProcess([], 0, b"false\n", b""),
            subprocess.CompletedProcess([], 0, b"false\n", b""),
        ]
        calls: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            calls.append(list(argv))
            return responses.pop(0)

        try:
            with mock.patch.object(RUNNER, "_run_checked", side_effect=fake_run), mock.patch.object(
                RUNNER,
                "_remove_staging_root",
                side_effect=OSError("synthetic staging removal failure"),
            ):
                with self.assertRaises(RUNNER.IsolationError) as raised:
                    RUNNER._reap_stale_containers(time.monotonic() + 30)
            self.assertEqual("STALE_PROCESSOR_REAP_FAILED", raised.exception.code)
            self.assertTrue(staging.exists())
            self.assertNotIn(["docker", "container", "rm", "--force", container_id], calls)
            self.assertNotIn(["docker", "volume", "rm", volume_name], calls)
        finally:
            if staging.exists():
                RUNNER._remove_staging_root(staging)

    def test_stale_reaper_handles_orphan_labeled_volume_phase(self) -> None:
        instance = "54321-" + "f" * 24
        staging = Path(tempfile.mkdtemp(prefix=f"tacua-isolated-input-{instance}-"))
        staging.chmod(0o700)
        (staging / "sensitive-fixture").write_bytes(b"synthetic")
        volume_name = f"tacua-private-payload-{instance}"
        volume_metadata = stale_volume_metadata(instance, staging)
        responses = [
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, (volume_name + "\n").encode(), b""),
            subprocess.CompletedProcess([], 0, json.dumps([volume_metadata]).encode(), b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
        ]
        calls: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            calls.append(list(argv))
            return responses.pop(0)

        try:
            with mock.patch.object(RUNNER, "_run_checked", side_effect=fake_run):
                RUNNER._reap_stale_containers(time.monotonic() + 30)
            self.assertFalse(staging.exists())
            self.assertIn(["docker", "volume", "rm", volume_name], calls)
        finally:
            if staging.exists():
                RUNNER._remove_staging_root(staging)

    def test_stale_reaper_rejects_an_ever_started_payload_carrier(self) -> None:
        instance = "54321-" + "9" * 24
        staging = Path(tempfile.mkdtemp(prefix=f"tacua-isolated-input-{instance}-"))
        staging.chmod(0o700)
        container_id = "9" * 64
        metadata = stale_container_metadata(instance, staging, container_id, role=RUNNER.CARRIER_ROLE)
        metadata["State"]["Status"] = "exited"
        metadata["State"]["StartedAt"] = "2026-07-22T00:00:00Z"
        try:
            with self.assertRaises(RUNNER.IsolationError) as raised:
                RUNNER._validate_stale_container(metadata, container_id)
            self.assertEqual("STALE_PROCESSOR_IDENTITY_INVALID", raised.exception.code)
        finally:
            RUNNER._remove_staging_root(staging)

    def test_exact_container_inspect_rejects_config_host_and_network_drift(self) -> None:
        instance = "54321-" + "4" * 24
        staging = Path(tempfile.mkdtemp(prefix=f"tacua-isolated-input-{instance}-"))
        staging.chmod(0o700)
        container_id = "4" * 64
        baseline = stale_container_metadata(instance, staging, container_id)
        cases: list[dict] = []
        for path, value in (
            (("Config", "User"), "0:0"),
            (("Config", "Cmd"), ["--input", "/different", "--model", "/different"]),
            (("Config", "Env"), ["LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/bin", "SECRET=x"]),
            (("HostConfig", "NanoCpus"), 0),
            (("HostConfig", "SecurityOpt"), []),
            (("HostConfig", "Devices"), [{"PathOnHost": "/dev/null"}]),
        ):
            changed = copy.deepcopy(baseline)
            changed[path[0]][path[1]] = value
            cases.append(changed)
        changed_label = copy.deepcopy(baseline)
        changed_label["Config"]["Labels"][RUNNER.CONFIG_DIGEST_LABEL] = "sha256:" + "0" * 64
        cases.append(changed_label)
        bridged = copy.deepcopy(baseline)
        bridged["NetworkSettings"]["Networks"] = {"bridge": {"IPAddress": "172.17.0.2"}}
        cases.append(bridged)
        try:
            for index, metadata in enumerate(cases):
                with self.subTest(index=index):
                    with self.assertRaises(RUNNER.IsolationError):
                        RUNNER._validate_stale_container(metadata, container_id)
        finally:
            RUNNER._remove_staging_root(staging)

    def test_completed_nonzero_processor_is_exactly_inspected_before_failure_decision(self) -> None:
        instance = "54321-" + "3" * 24
        staging = Path(tempfile.mkdtemp(prefix=f"tacua-isolated-input-{instance}-"))
        staging.chmod(0o700)
        container_id = "3" * 64
        metadata = stale_container_metadata(instance, staging, container_id)
        metadata["State"].update({"ExitCode": 7, "OOMKilled": False, "Error": ""})
        response = subprocess.CompletedProcess([], 0, json.dumps([metadata]).encode(), b"")
        try:
            with mock.patch.object(RUNNER, "_run_checked", return_value=response):
                RUNNER._validate_completed_processor(container_id, 7, time.monotonic() + 30)
            oom = copy.deepcopy(metadata)
            oom["State"]["OOMKilled"] = True
            with mock.patch.object(
                RUNNER,
                "_run_checked",
                return_value=subprocess.CompletedProcess([], 0, json.dumps([oom]).encode(), b""),
            ):
                with self.assertRaises(RUNNER.IsolationError):
                    RUNNER._validate_completed_processor(container_id, 7, time.monotonic() + 30)
        finally:
            RUNNER._remove_staging_root(staging)

    def test_stale_reaper_rejects_unhashable_runtime_identities_without_type_error(self) -> None:
        container_id = "2" * 64
        volume_name = "tacua-private-payload-54321-" + "2" * 24
        container_responses = [
            subprocess.CompletedProcess([], 0, (container_id + "\n").encode(), b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b'[{"Id":[]}]', b""),
        ]
        with mock.patch.object(RUNNER, "_run_checked", side_effect=container_responses):
            with self.assertRaises(RUNNER.IsolationError) as raised:
                RUNNER._reap_stale_containers(time.monotonic() + 30)
        self.assertEqual("STALE_PROCESSOR_IDENTITY_INVALID", raised.exception.code)

        volume_responses = [
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, (volume_name + "\n").encode(), b""),
            subprocess.CompletedProcess([], 0, b'[{"Name":[]}]', b""),
        ]
        with mock.patch.object(RUNNER, "_run_checked", side_effect=volume_responses):
            with self.assertRaises(RUNNER.IsolationError) as raised:
                RUNNER._reap_stale_containers(time.monotonic() + 30)
        self.assertEqual("STALE_PROCESSOR_IDENTITY_INVALID", raised.exception.code)

    def test_runtime_preflight_requires_rootless_cgroup_v2_systemd_controllers_and_seccomp(self) -> None:
        valid = {
            "CgroupDriver": "systemd",
            "CgroupVersion": "2",
            "CpuCfsQuota": True,
            "CpuCfsPeriod": True,
            "MemoryLimit": True,
            "PidsLimit": True,
            "SecurityOptions": ["name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"],
        }
        with mock.patch.object(
            RUNNER,
            "_run_checked",
            return_value=subprocess.CompletedProcess([], 0, json.dumps(valid).encode(), b""),
        ):
            RUNNER.validate_runtime_environment(time.monotonic() + 30)
        for field, value in (
            ("CgroupDriver", "none"),
            ("CgroupVersion", "1"),
            ("CpuCfsQuota", False),
            ("CpuCfsPeriod", False),
            ("MemoryLimit", False),
            ("PidsLimit", False),
            ("SecurityOptions", ["name=rootless"]),
        ):
            invalid = copy.deepcopy(valid)
            invalid[field] = value
            with self.subTest(field=field):
                with mock.patch.object(
                    RUNNER,
                    "_run_checked",
                    return_value=subprocess.CompletedProcess([], 0, json.dumps(invalid).encode(), b""),
                ):
                    with self.assertRaises(RUNNER.IsolationError) as raised:
                        RUNNER.validate_runtime_environment(time.monotonic() + 30)
                    self.assertEqual("PROCESSOR_RUNTIME_PREFLIGHT_FAILED", raised.exception.code)

    def test_carrier_and_processor_mount_and_root_modes_are_not_interchangeable(self) -> None:
        instance = "54321-" + "8" * 24
        staging = Path(tempfile.mkdtemp(prefix=f"tacua-isolated-input-{instance}-"))
        staging.chmod(0o700)
        carrier_id = "8" * 64
        processor_id = "7" * 64
        carrier = stale_container_metadata(instance, staging, carrier_id, role=RUNNER.CARRIER_ROLE)
        processor = stale_container_metadata(instance, staging, processor_id)
        real_docker_writable_carrier = copy.deepcopy(carrier)
        del real_docker_writable_carrier["HostConfig"]["Mounts"][0]["ReadOnly"]
        self.assertEqual(
            RUNNER.CARRIER_ROLE,
            RUNNER._validate_stale_container(real_docker_writable_carrier, carrier_id)[2],
        )
        cases = []
        carrier_read_only_root = copy.deepcopy(carrier)
        carrier_read_only_root["HostConfig"]["ReadonlyRootfs"] = True
        cases.append((carrier_read_only_root, carrier_id))
        carrier_read_only_volume = copy.deepcopy(carrier)
        carrier_read_only_volume["HostConfig"]["Mounts"][0]["ReadOnly"] = True
        cases.append((carrier_read_only_volume, carrier_id))
        carrier_with_tmpfs = copy.deepcopy(carrier)
        carrier_with_tmpfs["HostConfig"]["Tmpfs"] = {
            "/tmp": "rw,nosuid,nodev,noexec,size=268435456,uid=10002,gid=10002,mode=0700"
        }
        cases.append((carrier_with_tmpfs, carrier_id))
        processor_writable_volume = copy.deepcopy(processor)
        processor_writable_volume["HostConfig"]["Mounts"][0]["ReadOnly"] = False
        cases.append((processor_writable_volume, processor_id))
        try:
            for metadata, container_id in cases:
                with self.subTest(metadata=metadata):
                    with self.assertRaises(RUNNER.IsolationError):
                        RUNNER._validate_stale_container(metadata, container_id)
        finally:
            RUNNER._remove_staging_root(staging)

    def test_created_recovery_artifacts_are_inspected_before_sensitive_population(self) -> None:
        instance = "54321-" + "6" * 24
        staging = Path(tempfile.mkdtemp(prefix=f"tacua-isolated-input-{instance}-"))
        staging.chmod(0o700)
        carrier_id = "6" * 64
        processor_id = "5" * 64
        volume_name = f"tacua-private-payload-{instance}"
        carrier_metadata = stale_container_metadata(instance, staging, carrier_id, role=RUNNER.CARRIER_ROLE)
        processor_metadata = stale_container_metadata(instance, staging, processor_id)
        processor_metadata["State"] = {
            "Running": False,
            "Status": "created",
            "StartedAt": "0001-01-01T00:00:00Z",
        }
        responses = [
            subprocess.CompletedProcess(
                [],
                0,
                json.dumps([carrier_metadata]).encode(),
                b"",
            ),
            subprocess.CompletedProcess(
                [],
                0,
                json.dumps([stale_volume_metadata(instance, staging)]).encode(),
                b"",
            ),
            subprocess.CompletedProcess([], 0, json.dumps([processor_metadata]).encode(), b""),
            subprocess.CompletedProcess([], 0, json.dumps([stale_volume_metadata(instance, staging)]).encode(), b""),
        ]
        try:
            with mock.patch.object(RUNNER, "_run_checked", side_effect=responses) as invoked:
                RUNNER._validate_created_recovery_artifacts(
                    carrier_id,
                    processor_id,
                    volume_name,
                    instance,
                    staging,
                    time.monotonic() + 30,
                )
            self.assertEqual(["docker", "container", "inspect"], list(invoked.call_args_list[0].args[0])[:3])
            self.assertEqual(["docker", "volume", "inspect"], list(invoked.call_args_list[1].args[0])[:3])
            self.assertEqual(["docker", "container", "inspect"], list(invoked.call_args_list[2].args[0])[:3])
            self.assertEqual([], list(staging.iterdir()))
        finally:
            RUNNER._remove_staging_root(staging)

    def test_output_must_be_canonical_and_stays_within_the_closed_file_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copied = root / "copied"
            output = root / "output"
            copied.mkdir()
            output.mkdir()
            result = {"contract_version": "tacua.local-processing-result@1.0.0", "disposition": "checkpoint"}
            (copied / "result.json").write_bytes(RUNNER.canonical_json(result))
            (copied / "preview.png").write_bytes(b"preview")
            self.assertEqual(RUNNER.canonical_json(result), RUNNER._collect_output(copied, output))
            self.assertEqual(b"preview", (output / "preview.png").read_bytes())

    def test_attached_output_envelope_is_strict_digest_bound_and_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            output.mkdir()
            preview = b"preview"
            result = {
                "contract_version": "tacua.local-processing-result@1.0.0",
                "disposition": "terminal",
                "result": {
                    "candidates": [
                        {
                            "previews": [
                                {
                                    "body_file": "preview.txt",
                                    "content_digest": "sha256:" + hashlib.sha256(preview).hexdigest(),
                                    "size_bytes": len(preview),
                                }
                            ]
                        }
                    ]
                },
            }
            payload = output_envelope(result, [("preview.txt", preview)])
            self.assertEqual(
                RUNNER.canonical_json(result),
                RUNNER._validate_output_envelope(payload, output),
            )
            self.assertEqual(preview, (output / "preview.txt").read_bytes())

        invalid_payloads = [
            b'{"contract_version":"tacua.isolated-processing-output@1.0.0","previews":[],"result":{"value":1.0},"result_digest":"sha256:' + b"0" * 64 + b'"}',
            b'{"contract_version":"tacua.isolated-processing-output@1.0.0","previews":[],"result":{"value":9007199254740992},"result_digest":"sha256:' + b"0" * 64 + b'"}',
            b'{"contract_version":"tacua.isolated-processing-output@1.0.0","previews":[],"result":{"value":"e\xcc\x81"},"result_digest":"sha256:' + b"0" * 64 + b'"}',
            b"[" * 70 + b"null" + b"]" * 70,
        ]
        for index, invalid in enumerate(invalid_payloads):
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                with self.subTest(index=index):
                    with self.assertRaises(RUNNER.IsolationError) as raised:
                        RUNNER._validate_output_envelope(invalid, output)
                    self.assertEqual("INVALID_PROCESSOR_OUTPUT", raised.exception.code)
                    self.assertEqual([], list(output.iterdir()))

    def test_output_envelope_keeps_wrapper_v1_and_matches_nested_result_version(self) -> None:
        result_v11 = {
            "contract_version": RUNNER.SOURCE_RESULT_CONTRACT_V11,
            "disposition": "checkpoint",
            "input_digest": "sha256:" + "1" * 64,
            "job_digest": "sha256:" + "2" * 64,
            "job_id": "job_artifact_synthetic",
            "result": {"artifacts": [], "consumed_artifacts": []},
            "session_id": "session_artifact_synthetic",
            "stage_name": "align",
        }
        payload_v11 = output_envelope(result_v11)
        decoded = json.loads(payload_v11)
        self.assertEqual(RUNNER.OUTPUT_CONTRACT, decoded["contract_version"])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.assertEqual(
                RUNNER.canonical_json(result_v11),
                RUNNER._validate_output_envelope(
                    payload_v11,
                    output,
                    expected_result_contract=RUNNER.SOURCE_RESULT_CONTRACT_V11,
                ),
            )
            self.assertEqual([], list(output.iterdir()))

        result_v10 = copy.deepcopy(result_v11)
        result_v10["contract_version"] = RUNNER.SOURCE_RESULT_CONTRACT
        preview = b"not-admitted-for-v11-checkpoint"
        result_v11_with_preview = copy.deepcopy(result_v11)
        result_v11_with_preview["result"] = {
            "candidates": [
                {
                    "previews": [
                        {
                            "body_file": "unexpected.txt",
                            "content_digest": "sha256:"
                            + hashlib.sha256(preview).hexdigest(),
                            "size_bytes": len(preview),
                        }
                    ]
                }
            ]
        }
        mismatches = (
            (payload_v11, RUNNER.SOURCE_RESULT_CONTRACT),
            (output_envelope(result_v10), RUNNER.SOURCE_RESULT_CONTRACT_V11),
            (
                output_envelope(
                    result_v11_with_preview, [("unexpected.txt", preview)]
                ),
                RUNNER.SOURCE_RESULT_CONTRACT_V11,
            ),
        )
        for payload, expected in mismatches:
            with tempfile.TemporaryDirectory() as directory, self.subTest(
                expected=expected
            ):
                output = Path(directory)
                with self.assertRaises(RUNNER.IsolationError) as raised:
                    RUNNER._validate_output_envelope(
                        payload,
                        output,
                        expected_result_contract=expected,
                    )
                self.assertEqual("INVALID_PROCESSOR_OUTPUT", raised.exception.code)
                self.assertEqual([], list(output.iterdir()))

    def test_output_envelope_rejects_noncanonical_base64_and_digest_before_publication(self) -> None:
        preview = b"preview"
        result = {
            "disposition": "terminal",
            "result": {
                "candidates": [
                    {
                        "previews": [
                            {
                                "body_file": "preview.txt",
                                "content_digest": "sha256:" + hashlib.sha256(preview).hexdigest(),
                                "size_bytes": len(preview),
                            }
                        ]
                    }
                ]
            },
        }
        good = json.loads(output_envelope(result, [("preview.txt", preview)]))
        cases = []
        invalid_base64 = copy.deepcopy(good)
        invalid_base64["previews"][0]["content_base64"] = "cHJldmlldw"
        cases.append(invalid_base64)
        wrong_digest = copy.deepcopy(good)
        wrong_digest["previews"][0]["content_digest"] = "sha256:" + "0" * 64
        cases.append(wrong_digest)
        wrong_size = copy.deepcopy(good)
        wrong_size["previews"][0]["size_bytes"] = 8
        cases.append(wrong_size)
        missing_body = copy.deepcopy(good)
        missing_body["previews"] = []
        cases.append(missing_body)
        unreferenced_body = json.loads(output_envelope({"disposition": "checkpoint"}))
        unreferenced_body["previews"] = copy.deepcopy(good["previews"])
        cases.append(unreferenced_body)
        for case in cases:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                with self.assertRaises(RUNNER.IsolationError):
                    RUNNER._validate_output_envelope(RUNNER.canonical_json(case), output)
                self.assertEqual([], list(output.iterdir()))

    def test_invalid_late_output_entry_publishes_no_preview(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copied = root / "copied"
            output = root / "output"
            copied.mkdir()
            output.mkdir()
            (copied / "preview.png").write_bytes(b"preview")
            (copied / "result.json").write_bytes(RUNNER.canonical_json({"disposition": "checkpoint"}))
            (copied / "z-invalid-directory").mkdir()
            with self.assertRaises(RUNNER.IsolationError):
                RUNNER._collect_output(copied, output)
            self.assertEqual([], list(output.iterdir()))

    def test_non_finite_result_is_a_safe_error_and_publishes_no_preview(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copied = root / "copied"
            output = root / "output"
            copied.mkdir()
            output.mkdir()
            (copied / "preview.png").write_bytes(b"preview")
            (copied / "result.json").write_bytes(b'{"value":NaN}')
            with self.assertRaises(RUNNER.IsolationError) as raised:
                RUNNER._collect_output(copied, output)
            self.assertEqual("INVALID_PROCESSOR_OUTPUT", raised.exception.code)
            self.assertEqual([], list(output.iterdir()))

    def test_preview_publication_stages_on_destination_filesystem_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copied = root / "copied"
            output = root / "output"
            copied.mkdir()
            output.mkdir()
            (copied / "a.png").write_bytes(b"a")
            (copied / "b.png").write_bytes(b"b")
            (copied / "result.json").write_bytes(RUNNER.canonical_json({"disposition": "checkpoint"}))
            real_replace = RUNNER.os.replace
            destinations: list[Path] = []

            def flaky_replace(source, destination):
                destination_path = Path(destination)
                destinations.append(destination_path)
                if destination_path.name == "b.png":
                    raise OSError("synthetic rename failure")
                return real_replace(source, destination)

            with mock.patch.object(RUNNER.os, "replace", side_effect=flaky_replace):
                with self.assertRaises(RUNNER.IsolationError) as raised:
                    RUNNER._collect_output(copied, output)
            self.assertEqual("PREVIEW_PUBLICATION_FAILED", raised.exception.code)
            self.assertTrue(all(path.parent == output for path in destinations))
            self.assertEqual([], list(output.iterdir()))

    def test_resolved_compose_profile_is_fail_closed(self) -> None:
        profile = resolved_profile()
        PROFILE.validate_profile(profile)
        cases = []
        networked = copy.deepcopy(profile)
        networked["services"][PROFILE.SERVICE]["network_mode"] = "bridge"
        cases.append(networked)
        socket = copy.deepcopy(profile)
        socket["services"][PROFILE.SERVICE]["volumes"] = ["/var/run/docker.sock:/var/run/docker.sock"]
        cases.append(socket)
        secret = copy.deepcopy(profile)
        secret["services"][PROFILE.SERVICE]["secrets"] = ["provider-key"]
        cases.append(secret)
        unbounded = copy.deepcopy(profile)
        unbounded["services"][PROFILE.SERVICE]["mem_limit"] = "8g"
        cases.append(unbounded)
        mutable_image = copy.deepcopy(profile)
        mutable_image["services"][PROFILE.SERVICE]["image"] = "processor:latest"
        cases.append(mutable_image)
        for field, value in (
            ("pid", "host"),
            ("userns_mode", "host"),
            ("uts", "host"),
            ("cgroup", "host"),
            ("env_file", ["/tmp/untrusted.env"]),
            ("group_add", ["999"]),
            ("sysctls", {"kernel.unprivileged_userns_clone": "1"}),
            ("extra_hosts", ["metadata:169.254.169.254"]),
            ("devices", ["/dev/null:/dev/host-device"]),
        ):
            expanded = copy.deepcopy(profile)
            expanded["services"][PROFILE.SERVICE][field] = value
            cases.append(expanded)
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(PROFILE.ProfileError):
                    PROFILE.validate_profile(case)


if __name__ == "__main__":
    unittest.main()
