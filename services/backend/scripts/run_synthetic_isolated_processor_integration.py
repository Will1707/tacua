#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build and run the synthetic Docker fixture, including crash recovery."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[3]
RUNNER_PATH = ROOT / "services" / "backend" / "scripts" / "run_isolated_processor.py"
FIXTURE_CONTEXT = ROOT / "services" / "backend" / "tests" / "fixtures" / "isolated-processor"


def _load_runner():
    specification = importlib.util.spec_from_file_location("tacua_isolation_integration_runner", RUNNER_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError("isolated runner module cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


RUNNER = _load_runner()


def _docker(argv: list[str], *, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["docker", *argv],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=check,
    )


def _sealed_input(descriptor: int, evidence: bytes) -> dict:
    value = {
        "binding": {"job_id": "job_synthetic_docker"},
        "capture": {
            "diagnostics": [],
            "segments": [
                {
                    "content_digest": "sha256:" + hashlib.sha256(evidence).hexdigest(),
                    "read_only_path": f"/dev/fd/{descriptor}",
                    "segment_id": "segment_synthetic_docker",
                }
            ],
        },
        "contract_version": RUNNER.SOURCE_INPUT_CONTRACT,
        "input_digest": "sha256:" + "0" * 64,
    }
    subject = copy.deepcopy(value)
    subject.pop("input_digest")
    value["input_digest"] = "sha256:" + hashlib.sha256(RUNNER.canonical_json(subject)).hexdigest()
    return value


def _command(image: str, model: Path, *, sleep_seconds: int) -> dict:
    return {
        "argv": [
            "/opt/tacua-synthetic-processor.py",
            "--input",
            RUNNER.INPUT_PLACEHOLDER,
            "--model",
            RUNNER.MODEL_PLACEHOLDER,
            "--sleep-seconds",
            str(sleep_seconds),
        ],
        "contract_version": RUNNER.COMMAND_CONTRACT,
        "image": image,
        "model_digest": "sha256:" + hashlib.sha256(model.read_bytes()).hexdigest(),
        "model_id": "synthetic-docker-model",
        "model_path": str(model),
        "timeout_seconds": 45,
    }


def _runner_process(
    command_path: Path,
    input_path: Path,
    output_directory: Path,
    descriptor: int,
) -> subprocess.Popen[bytes]:
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        RUNNER.OUTER_TIMEOUT_ENV: str(RUNNER.OUTER_ADAPTER_TIMEOUT_SECONDS),
    }
    return subprocess.Popen(
        [
            sys.executable,
            "-B",
            str(RUNNER_PATH),
            "--command-file",
            str(command_path),
            "--input",
            str(input_path),
            "--output-directory",
            str(output_directory),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        close_fds=True,
        pass_fds=(descriptor,),
        start_new_session=True,
    )


def _fixture_container_ids() -> list[str]:
    result = _docker(
        [
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            f"label={RUNNER.PRIVATE_LABEL}=true",
            "--filter",
            f"label={RUNNER.CONTRACT_LABEL}={RUNNER.COMMAND_CONTRACT}",
        ],
        timeout=15,
    )
    return result.stdout.decode("ascii").splitlines()


def _fixture_volume_names() -> list[str]:
    result = _docker(
        [
            "volume",
            "ls",
            "--quiet",
            "--filter",
            f"label={RUNNER.PRIVATE_LABEL}=true",
            "--filter",
            f"label={RUNNER.CONTRACT_LABEL}={RUNNER.COMMAND_CONTRACT}",
        ],
        timeout=15,
    )
    return result.stdout.decode("ascii").splitlines()


def _role_container_ids(role: str, *, running_only: bool) -> list[str]:
    argv = [
        "container",
        "ls",
        "--no-trunc",
        "--quiet",
    ]
    if not running_only:
        argv.append("--all")
    argv.extend(
        [
            "--filter",
            f"label={RUNNER.PRIVATE_LABEL}=true",
            "--filter",
            f"label={RUNNER.CONTRACT_LABEL}={RUNNER.COMMAND_CONTRACT}",
            "--filter",
            f"label={RUNNER.ROLE_LABEL}={role}",
        ]
    )
    return _docker(argv, timeout=10).stdout.decode("ascii").splitlines()


def _validate_live_artifact(container_id: str, expected_role: str) -> tuple[str, str]:
    payload = json.loads(_docker(["container", "inspect", container_id], timeout=15).stdout)
    if not isinstance(payload, list) or len(payload) != 1:
        raise RuntimeError("synthetic container inspect was ambiguous")
    _full_id, _instance, role, _staging, volume_name = RUNNER._validate_stale_container(
        payload[0],
        container_id,
    )
    if role != expected_role:
        raise RuntimeError("synthetic container role differed")
    volumes = json.loads(_docker(["volume", "inspect", volume_name], timeout=15).stdout)
    if not isinstance(volumes, list) or len(volumes) != 1:
        raise RuntimeError("synthetic volume inspect was ambiguous")
    RUNNER._validate_stale_volume(volumes[0], volume_name)
    return role, volume_name


def _assert_pristine_fixture_labels() -> None:
    containers = _fixture_container_ids()
    volumes = _fixture_volume_names()
    if (
        len(set(containers)) != len(containers)
        or any(not RUNNER.CONTAINER_ID_RE.fullmatch(identifier) for identifier in containers)
        or len(set(volumes)) != len(volumes)
        or any(not RUNNER.VOLUME_NAME_RE.fullmatch(name) for name in volumes)
    ):
        raise RuntimeError("refusing integration: Tacua recovery label listing is not exact")
    if containers or volumes:
        raise RuntimeError("refusing integration: pre-existing Tacua private recovery labels are not empty")


def _cleanup_fixture_artifacts(owned_runner_pids: set[int]) -> None:
    containers = _fixture_container_ids()
    volumes = _fixture_volume_names()
    owned_pid_prefixes = {str(pid) + "-" for pid in owned_runner_pids}
    for container_id in containers:
        payload = json.loads(_docker(["container", "inspect", container_id], timeout=15).stdout)
        if not isinstance(payload, list) or len(payload) != 1:
            raise RuntimeError("refusing cleanup: labeled container inspect is ambiguous")
        _full_id, instance, _role, _staging, _volume = RUNNER._validate_stale_container(
            payload[0], container_id
        )
        if not any(instance.startswith(prefix) for prefix in owned_pid_prefixes):
            raise RuntimeError("refusing cleanup: labeled container is not integration-owned")
    for volume_name in volumes:
        payload = json.loads(_docker(["volume", "inspect", volume_name], timeout=15).stdout)
        if not isinstance(payload, list) or len(payload) != 1:
            raise RuntimeError("refusing cleanup: labeled volume inspect is ambiguous")
        _name, instance, _staging = RUNNER._validate_stale_volume(payload[0], volume_name)
        if not any(instance.startswith(prefix) for prefix in owned_pid_prefixes):
            raise RuntimeError("refusing cleanup: labeled volume is not integration-owned")
    RUNNER._reap_stale_containers(
        time.monotonic() + 60,
        expected_container_ids=set(containers),
        expected_volume_names=set(volumes),
    )


def main() -> int:
    tag = f"tacua-isolated-processor-fixture:integration-{os.getpid()}-{os.urandom(4).hex()}"
    stale_id: str | None = None
    image_built = False
    entry_was_clean = False
    runners: list[subprocess.Popen[bytes]] = []
    try:
        _assert_pristine_fixture_labels()
        entry_was_clean = True
        RUNNER.validate_runtime_environment(time.monotonic() + 30)
        _docker(["build", "--pull=false", "--tag", tag, str(FIXTURE_CONTEXT)], timeout=300)
        image_built = True
        image = _docker(["image", "inspect", "--format", "{{.Id}}", tag], timeout=15).stdout.decode("ascii").strip()
        if not RUNNER.IMAGE_RE.fullmatch(image):
            raise RuntimeError("synthetic image did not resolve to one immutable image ID")

        with tempfile.TemporaryDirectory(prefix="tacua-isolation-integration-") as directory:
            root = Path(directory)
            model = root / "model.bin"
            evidence_path = root / "evidence.bin"
            input_path = root / "input.json"
            stale_command_path = root / "stale-command.json"
            command_path = root / "command.json"
            stale_output = root / "stale-output"
            output = root / "output"
            model.write_bytes(b"synthetic model fixture only\n")
            evidence = b"synthetic evidence fixture only\n"
            evidence_path.write_bytes(evidence)
            stale_output.mkdir()
            output.mkdir()
            descriptor = os.open(evidence_path, os.O_RDONLY)
            try:
                input_path.write_bytes(RUNNER.canonical_json(_sealed_input(descriptor, evidence)))
                stale_command_path.write_bytes(RUNNER.canonical_json(_command(image, model, sleep_seconds=30)))
                command_path.write_bytes(RUNNER.canonical_json(_command(image, model, sleep_seconds=0)))
                stale_command_path.chmod(0o600)
                command_path.chmod(0o600)

                stale = _runner_process(stale_command_path, input_path, stale_output, descriptor)
                runners.append(stale)
                deadline = time.monotonic() + 30
                carrier_observed = False
                while time.monotonic() < deadline:
                    carriers = _role_container_ids(RUNNER.CARRIER_ROLE, running_only=False)
                    if carriers:
                        if len(carriers) != 1:
                            raise RuntimeError("synthetic carrier identity was ambiguous")
                        _validate_live_artifact(carriers[0], RUNNER.CARRIER_ROLE)
                        if _role_container_ids(RUNNER.CARRIER_ROLE, running_only=True):
                            raise RuntimeError("synthetic payload carrier was started")
                        carrier_observed = True
                        break
                    if stale.poll() is not None:
                        stdout, stderr = stale.communicate()
                        raise RuntimeError(f"fixture runner exited before carrier observation: {stdout!r} {stderr!r}")
                    time.sleep(0.01)
                if not carrier_observed:
                    raise RuntimeError("synthetic never-started payload carrier was not observed")
                while time.monotonic() < deadline:
                    running = _role_container_ids(RUNNER.PROCESSOR_ROLE, running_only=True)
                    if running:
                        if len(running) != 1:
                            raise RuntimeError("synthetic running processor identity was ambiguous")
                        stale_id = running[0]
                        _validate_live_artifact(stale_id, RUNNER.PROCESSOR_ROLE)
                        if _role_container_ids(RUNNER.CARRIER_ROLE, running_only=False):
                            raise RuntimeError("payload carrier remained when the final processor started")
                        break
                    if stale.poll() is not None:
                        stdout, stderr = stale.communicate()
                        raise RuntimeError(f"fixture runner exited before interruption: {stdout!r} {stderr!r}")
                    time.sleep(0.1)
                if stale_id is None:
                    raise RuntimeError("synthetic processor did not reach the running state")
                os.killpg(stale.pid, signal.SIGKILL)
                stale.communicate(timeout=10)
                os.lseek(descriptor, 0, os.SEEK_SET)

                recovered = _runner_process(command_path, input_path, output, descriptor)
                runners.append(recovered)
                stdout, stderr = recovered.communicate(timeout=220)
                if recovered.returncode != 0:
                    raise RuntimeError(f"recovery runner failed: {stderr.decode('utf-8', 'replace')}")
                expected = RUNNER.canonical_json(
                    {
                        "contract_version": "tacua.local-processing-result@1.0.0",
                        "disposition": "checkpoint",
                        "fixture": "isolated-docker-passed",
                        "payload_read_only": True,
                        "root_read_only": True,
                        "uid": RUNNER.PROCESSOR_UID,
                        "result": {
                            "candidates": [
                                {
                                    "previews": [
                                        {
                                            "body_file": "synthetic-preview.txt",
                                            "content_digest": "sha256:"
                                            + hashlib.sha256(b"isolated preview\n").hexdigest(),
                                            "size_bytes": len(b"isolated preview\n"),
                                        }
                                    ]
                                }
                            ]
                        },
                    }
                )
                if stdout != expected or (output / "synthetic-preview.txt").read_bytes() != b"isolated preview\n":
                    raise RuntimeError("synthetic processor output was not copied and validated exactly")
                stale_id = None
                if _fixture_container_ids() or _fixture_volume_names():
                    raise RuntimeError("labeled processor artifact remained after successful recovery")
            finally:
                os.close(descriptor)
        print("synthetic isolated processor Docker integration valid", file=sys.stderr)
        return 0
    finally:
        for runner in runners:
            if runner.poll() is None:
                try:
                    os.killpg(runner.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                runner.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        try:
            if image_built and entry_was_clean and runners:
                lock_descriptor = RUNNER._acquire_runner_lock()
                try:
                    _cleanup_fixture_artifacts({runner.pid for runner in runners})
                finally:
                    RUNNER._release_runner_lock(lock_descriptor)
        finally:
            if image_built:
                _docker(["image", "rm", "--force", tag], timeout=60, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
