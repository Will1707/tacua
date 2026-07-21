#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the safe local-only conformance phase for Tacua EXP-007."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


EXPERIMENT_LABEL = "tacua-exp007"
PROBE_VERSION = "0.1.0"
IMAGE_TAG = f"tacua-exp007-probe:{PROBE_VERSION}"
CONTAINERS = [
    "tacua-exp007-offline",
    "tacua-exp007-recreated",
    "tacua-exp007-port-owner",
    "tacua-exp007-port-conflict",
    "tacua-exp007-migrate-success",
    "tacua-exp007-migrate-failure",
    "tacua-exp007-rollback",
    "tacua-exp007-restore-fresh",
    "tacua-exp007-corrupt-restore",
    "tacua-exp007-incompatible-restore",
    "tacua-exp007-config-missing",
    "tacua-exp007-config-invalid",
    "tacua-exp007-volume-permission",
    "tacua-exp007-disk-quota",
    "tacua-exp007-backup-pre",
    "tacua-exp007-backup-final",
    "tacua-exp007-fixture-corrupt",
    "tacua-exp007-fixture-incompatible",
    "tacua-exp007-license-inventory",
    "tacua-exp007-backup-size",
]
VOLUMES = [
    "tacua-exp007-state-a",
    "tacua-exp007-state-restored",
    "tacua-exp007-backups",
]
PORT = 18707

SOURCE_DIR = Path(__file__).resolve().parent
WORKSPACE = SOURCE_DIR.parent.parent
RESULT_DIR = WORKSPACE / "artifacts" / "docker-topology-probe" / "EXP-007"
RUNTIME_DIR = SOURCE_DIR / ".runtime"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def scrub(text: str, token: str | None = None) -> str:
    value = text.replace(str(WORKSPACE), "$WORKSPACE").replace(str(RUNTIME_DIR), "$RUNTIME")
    if token:
        value = value.replace(token, "[REDACTED_SYNTHETIC_TOKEN]")
    return value


class Harness:
    def __init__(self) -> None:
        self.started = time.monotonic()
        self.run_id = f"tacua-exp007-local-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        self.token = secrets.token_hex(32)
        self.command_log: list[dict[str, Any]] = []
        self.tests: list[dict[str, Any]] = []
        self.measurements: dict[str, Any] = {}
        self.created_containers: set[str] = set()
        self.created_volumes: set[str] = set()
        self.image_id = ""
        self.archive_checksum = ""
        self.config_path = RUNTIME_DIR / "config.json"
        self.invalid_config_path = RUNTIME_DIR / "invalid-config.json"

    def command(
        self,
        args: list[str],
        case_id: str,
        *,
        expected: int | None = 0,
        timeout: float = 120,
        record_output: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        started = time.monotonic()
        completed = subprocess.run(
            args,
            cwd=WORKSPACE,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        elapsed = round(time.monotonic() - started, 4)
        entry: dict[str, Any] = {
            "case_id": case_id,
            "command": [scrub(part, self.token) for part in args],
            "exit_code": completed.returncode,
            "elapsed_seconds": elapsed,
        }
        if record_output:
            entry["stdout"] = scrub(completed.stdout[-8000:], self.token)
            entry["stderr"] = scrub(completed.stderr[-8000:], self.token)
        self.command_log.append(entry)
        if expected is not None and completed.returncode != expected:
            raise RuntimeError(
                f"{case_id}: expected exit {expected}, got {completed.returncode}: "
                f"{scrub(completed.stderr[-1000:], self.token)}"
            )
        return completed

    def expect_failure(self, args: list[str], case_id: str, expected_text: str | None = None) -> subprocess.CompletedProcess[str]:
        completed = self.command(args, case_id, expected=None)
        if completed.returncode == 0:
            raise RuntimeError(f"{case_id}: command unexpectedly succeeded")
        combined = completed.stdout + completed.stderr
        if expected_text and expected_text not in combined:
            raise RuntimeError(f"{case_id}: expected typed error {expected_text!r} was absent")
        return completed

    def test(self, case_id: str, status: str, evidence: dict[str, Any] | str) -> None:
        self.tests.append({"case_id": case_id, "status": status, "evidence": evidence})

    def docker_labels(self) -> list[str]:
        return ["--label", f"tacua.experiment={EXPERIMENT_LABEL}", "--label", f"tacua.run={self.run_id}"]

    def env_args(self, case_id: str) -> list[str]:
        return [
            "-e",
            "TACUA_PROBE_CONFIG=/run/secrets/tacua_probe_config",
            "-e",
            f"TACUA_PROBE_CASE_ID={case_id}",
            "-e",
            f"TACUA_PROBE_IMAGE_ID={self.image_id}",
            "-e",
            "TACUA_PROBE_HOST_CLASS=local-docker-desktop",
        ]

    def config_mount(self, path: Path | None = None) -> list[str]:
        actual = path or self.config_path
        return ["--mount", f"type=bind,src={actual},dst=/run/secrets/tacua_probe_config,readonly"]

    def standard_isolation(self) -> list[str]:
        return ["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m"]

    def check_absent(self, kind: str, name: str) -> None:
        args = ["docker", kind, "inspect", name]
        result = self.command(args, f"preflight-{kind}-{name}", expected=None, record_output=False)
        if result.returncode == 0:
            raise RuntimeError(f"refusing to reuse pre-existing Docker {kind} {name}")

    def create_volume(self, name: str) -> None:
        self.command(
            ["docker", "volume", "create", *self.docker_labels(), name],
            f"create-volume-{name}",
        )
        self.created_volumes.add(name)

    def ownership_label(self, kind: str, name: str) -> str | None:
        if kind == "container":
            fmt = "{{index .Config.Labels \"tacua.experiment\"}}"
        elif kind == "volume":
            fmt = "{{index .Labels \"tacua.experiment\"}}"
        else:
            fmt = "{{index .Config.Labels \"tacua.experiment\"}}"
        result = self.command(["docker", kind, "inspect", "--format", fmt, name], f"label-{kind}-{name}", expected=None)
        return result.stdout.strip() if result.returncode == 0 else None

    def safe_remove_container(self, name: str) -> bool:
        label = self.ownership_label("container", name)
        if label is None:
            return False
        if label != EXPERIMENT_LABEL or name not in self.created_containers:
            raise RuntimeError(f"refusing to remove container without run ownership: {name}")
        self.command(["docker", "rm", "-f", name], f"cleanup-container-{name}")
        return True

    def safe_remove_volume(self, name: str) -> bool:
        label = self.ownership_label("volume", name)
        if label is None:
            return False
        if label != EXPERIMENT_LABEL or name not in self.created_volumes:
            raise RuntimeError(f"refusing to remove volume without run ownership: {name}")
        self.command(["docker", "volume", "rm", name], f"cleanup-volume-{name}")
        self.created_volumes.discard(name)
        return True

    def run_once(
        self,
        name: str,
        case_id: str,
        command: list[str],
        *,
        volumes: list[tuple[str, str]] | None = None,
        config_path: Path | None = None,
        extra: list[str] | None = None,
        expected_failure: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = ["docker", "run", "--name", name, *self.docker_labels(), *self.standard_isolation()]
        if config_path is not False:  # type: ignore[comparison-overlap]
            args.extend(self.config_mount(config_path))
            args.extend(self.env_args(case_id))
        if volumes:
            for source, target in volumes:
                args.extend(["--mount", f"type=volume,src={source},dst={target}"])
        if extra:
            args.extend(extra)
        args.extend([IMAGE_TAG, *command])
        self.created_containers.add(name)
        if expected_failure:
            return self.expect_failure(args, case_id, expected_failure)
        return self.command(args, case_id)

    def wait_healthy(self, name: str, case_id: str, timeout: float = 25) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last = "unknown"
        while time.monotonic() < deadline:
            result = self.command(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", name],
                f"{case_id}-health-status",
                expected=None,
                record_output=False,
            )
            if result.returncode == 0:
                last = result.stdout.strip()
                if last == "healthy":
                    response = self.command(
                        [
                            "docker",
                            "exec",
                            name,
                            "python3",
                            "-c",
                            "import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:8707/healthz', timeout=1)), sort_keys=True))",
                        ],
                        f"{case_id}-health-request",
                    )
                    return json.loads(response.stdout)
                if last == "unhealthy":
                    break
            time.sleep(0.25)
        logs = self.command(["docker", "logs", name], f"{case_id}-failed-logs", expected=None).stderr
        raise RuntimeError(f"{case_id}: did not become healthy (last={last}): {logs[-1000:]}")

    def stop_gracefully(self, name: str, case_id: str) -> str:
        self.command(["docker", "stop", "--time", "3", name], f"{case_id}-stop", timeout=10)
        completed = self.command(["docker", "logs", name], f"{case_id}-logs", expected=0)
        logs = completed.stdout + completed.stderr
        # The probe writes structured logs to stderr, which Docker preserves as
        # a separate stream when client output is captured programmatically.
        if '"state_transition":"stopped"' not in logs:
            raise RuntimeError(f"{case_id}: graceful stop log was absent")
        return logs

    def state_checksum(self, volume: str, name: str, case_id: str) -> str:
        result = self.run_once(
            name,
            case_id,
            ["checksum"],
            volumes=[(volume, "/data")],
        )
        value = result.stdout.strip()
        if len(value) != 64:
            raise RuntimeError(f"{case_id}: invalid checksum output")
        return value

    def preflight(self) -> dict[str, Any]:
        RESULT_DIR.mkdir(parents=True, exist_ok=True)
        if RUNTIME_DIR.exists():
            raise RuntimeError(f"refusing to reuse runtime directory: {RUNTIME_DIR}")
        RUNTIME_DIR.mkdir(mode=0o700)
        self.config_path.write_text(
            json.dumps(
                {
                    "instance_id": "tacua-exp007-local-primary",
                    "listen_port": 8707,
                    "marker": "tacua-exp007-synthetic-marker",
                    "synthetic_token": self.token,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.config_path.chmod(0o600)
        self.invalid_config_path.write_text("{invalid-json\n", encoding="utf-8")
        self.invalid_config_path.chmod(0o600)
        for name in CONTAINERS:
            self.check_absent("container", name)
        for name in VOLUMES:
            self.check_absent("volume", name)
        self.check_absent("image", IMAGE_TAG)
        docker_version = self.command(["docker", "version", "--format", "{{json .}}"], "preflight-docker-version")
        docker_info = self.command(
            [
                "docker",
                "info",
                "--format",
                "{{json .DriverStatus}}|{{.Architecture}}|{{.OSType}}|{{.NCPU}}|{{.MemTotal}}|{{.DockerRootDir}}",
            ],
            "preflight-docker-info",
        )
        revision = self.command(["git", "rev-parse", "--verify", "HEAD"], "preflight-source-revision", expected=None)
        dirty = self.command(["git", "status", "--porcelain", "--", str(SOURCE_DIR)], "preflight-source-dirty")
        disk = shutil.disk_usage(WORKSPACE)
        return {
            "run_id": self.run_id,
            "started_at": utc_now(),
            "source_revision": revision.stdout.strip() if revision.returncode == 0 else "uncommitted-workspace",
            "source_dirty": bool(dirty.stdout.strip()),
            "host": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
                "docker_version": json.loads(docker_version.stdout),
                "docker_info_summary": scrub(docker_info.stdout.strip()),
                "workspace_disk_free_bytes": disk.free,
            },
            "network_constraint": "probe runtime tested with Docker --network none; base image pull/build used host network",
            "local_phase_authorized": True,
            "remote_phase_authorized": False,
            "remote_phase_blocker": "No generic remote Linux/container host or registry/transport scope was authorized.",
        }

    def build(self, preflight: dict[str, Any]) -> dict[str, Any]:
        build_time = utc_now()
        # Pull explicitly before the BuildKit build so the resolved base digest
        # remains inspectable for provenance; BuildKit alone may keep it only in
        # its private content store.
        self.command(
            ["docker", "pull", "python:3.13-alpine"],
            "pull-base-image",
            timeout=600,
        )
        started = time.monotonic()
        self.command(
            [
                "docker",
                "build",
                "--pull",
                "--label",
                f"tacua.experiment={EXPERIMENT_LABEL}",
                "--build-arg",
                f"PROBE_VERSION={PROBE_VERSION}",
                "--build-arg",
                f"SOURCE_REVISION={preflight['source_revision']}",
                "--build-arg",
                f"BUILD_TIME={build_time}",
                "--tag",
                IMAGE_TAG,
                str(SOURCE_DIR),
            ],
            "build-image",
            timeout=600,
        )
        self.measurements["image_build_seconds"] = round(time.monotonic() - started, 4)
        inspect = self.command(["docker", "image", "inspect", IMAGE_TAG], "inspect-image")
        image = json.loads(inspect.stdout)[0]
        self.image_id = image["Id"]
        self.measurements["image_size_bytes"] = image["Size"]
        labels = image["Config"].get("Labels", {})
        if labels.get("tacua.experiment") != EXPERIMENT_LABEL or labels.get("tacua.production") != "false":
            raise RuntimeError("image experiment/non-production labels are missing")
        if image["Config"].get("User") != "65532:65532":
            raise RuntimeError("image is not configured for the expected non-root UID/GID")
        history = self.command(["docker", "history", "--no-trunc", IMAGE_TAG], "inspect-image-history")
        if self.token in history.stdout + history.stderr:
            raise RuntimeError("synthetic runtime token appeared in image history")
        archive = RUNTIME_DIR / "tacua-exp007-probe.tar"
        self.command(["docker", "save", "--output", str(archive), IMAGE_TAG], "save-image", timeout=300, record_output=False)
        archive_hash = hashlib.sha256()
        token_bytes = self.token.encode("utf-8")
        token_found = False
        with archive.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                archive_hash.update(chunk)
                token_found = token_found or token_bytes in chunk
        self.archive_checksum = archive_hash.hexdigest()
        archive_size = archive.stat().st_size
        archive.unlink()
        if token_found:
            raise RuntimeError("synthetic runtime token appeared in saved image layers")
        base = self.command(["docker", "image", "inspect", "python:3.13-alpine"], "inspect-base-image")
        base_image = json.loads(base.stdout)[0]
        licenses = self.command(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                "tacua-exp007-license-inventory",
                *self.docker_labels(),
                "--entrypoint",
                "/bin/sh",
                IMAGE_TAG,
                "-c",
                'for package in $(apk info); do apk info -a "$package"; done',
            ],
            "license-inventory",
        )
        self.created_containers.add("tacua-exp007-license-inventory")
        return {
            "image_tag": IMAGE_TAG,
            "image_id_content_digest": self.image_id,
            "saved_artifact_sha256": self.archive_checksum,
            "saved_artifact_bytes": archive_size,
            "architecture": image["Architecture"],
            "os": image["Os"],
            "created": image["Created"],
            "config": image["Config"],
            "repo_digests": image.get("RepoDigests", []),
            "base_image_id": base_image["Id"],
            "base_repo_digests": base_image.get("RepoDigests", []),
            "history": scrub(history.stdout, self.token),
            "installed_package_metadata": scrub(licenses.stdout, self.token),
            "secret_scan": {
                "runtime_token_in_history": False,
                "runtime_token_in_saved_layers": False,
                "note": "Static scan covered the generated synthetic token value; configuration key names remain in source by design.",
            },
        }

    def conformance(self) -> None:
        self.create_volume("tacua-exp007-state-a")
        self.create_volume("tacua-exp007-backups")

        start = time.monotonic()
        offline_args = [
            "docker",
            "run",
            "-d",
            "--name",
            "tacua-exp007-offline",
            *self.docker_labels(),
            "--network",
            "none",
            *self.standard_isolation(),
            *self.config_mount(),
            *self.env_args("offline-start"),
            "--mount",
            "type=volume,src=tacua-exp007-state-a,dst=/data",
            "--mount",
            "type=volume,src=tacua-exp007-backups,dst=/backup",
            IMAGE_TAG,
            "serve",
        ]
        self.command(offline_args, "offline-start")
        self.created_containers.add("tacua-exp007-offline")
        health = self.wait_healthy("tacua-exp007-offline", "offline-start")
        self.measurements["offline_start_to_health_seconds"] = round(time.monotonic() - start, 4)
        version_result = self.command(
            [
                "docker",
                "exec",
                "tacua-exp007-offline",
                "python3",
                "-c",
                "import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:8707/version', timeout=1)), sort_keys=True))",
            ],
            "offline-version-response",
        )
        version_response = json.loads(version_result.stdout)
        if version_response.get("probe_version") != PROBE_VERSION:
            raise RuntimeError("version endpoint did not report the built probe version")
        identity = self.command(["docker", "exec", "tacua-exp007-offline", "id"], "non-root-runtime")
        if "uid=65532" not in identity.stdout:
            raise RuntimeError("runtime user is not UID 65532")
        stats = self.command(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}", "tacua-exp007-offline"],
            "idle-resource-sample",
        )
        self.measurements["idle_resource_sample"] = json.loads(stats.stdout)
        original_checksum = health["state_checksum"]
        restart_start = time.monotonic()
        self.command(
            ["docker", "restart", "--time", "3", "tacua-exp007-offline"],
            "container-restart",
            timeout=10,
        )
        restarted_health = self.wait_healthy("tacua-exp007-offline", "container-restart")
        self.measurements["restart_to_health_seconds"] = round(time.monotonic() - restart_start, 4)
        if restarted_health["state_checksum"] != original_checksum:
            raise RuntimeError("persistent marker checksum changed across container restart")
        logs = self.stop_gracefully("tacua-exp007-offline", "graceful-stop")
        self.test("offline-start-health-version", "passed", {"health": health, "version": version_response})
        self.test("non-root-read-only", "passed", {"runtime_identity": identity.stdout.strip(), "read_only_rootfs": True})
        self.test("graceful-stop", "passed", {"stopped_log_present": True, "log_excerpt": logs[-600:]})
        self.test(
            "container-restart-persistence",
            "passed",
            {"before_checksum": original_checksum, "after_checksum": restarted_health["state_checksum"]},
        )

        recreate_start = time.monotonic()
        recreate_args = [
            "docker",
            "run",
            "-d",
            "--name",
            "tacua-exp007-recreated",
            *self.docker_labels(),
            "--network",
            "none",
            *self.standard_isolation(),
            *self.config_mount(),
            *self.env_args("recreate-persistence"),
            "--mount",
            "type=volume,src=tacua-exp007-state-a,dst=/data",
            "--mount",
            "type=volume,src=tacua-exp007-backups,dst=/backup",
            IMAGE_TAG,
            "serve",
        ]
        self.command(recreate_args, "recreate-persistence")
        self.created_containers.add("tacua-exp007-recreated")
        recreated_health = self.wait_healthy("tacua-exp007-recreated", "recreate-persistence")
        self.measurements["recreate_to_health_seconds"] = round(time.monotonic() - recreate_start, 4)
        if recreated_health["state_checksum"] != original_checksum:
            raise RuntimeError("persistent marker checksum changed across recreation")
        self.test(
            "restart-recreate-persistence",
            "passed",
            {"before_checksum": original_checksum, "after_checksum": recreated_health["state_checksum"]},
        )

        backup_start = time.monotonic()
        pre_backup = self.command(
            [
                "docker",
                "exec",
                "tacua-exp007-recreated",
                "python3",
                "/opt/tacua-probe/probe.py",
                "backup",
                "--output",
                "/backup/pre-migration.json",
            ],
            "backup-pre-migration",
        )
        self.measurements["pre_migration_backup_seconds"] = round(time.monotonic() - backup_start, 4)
        pre_backup_checksum = pre_backup.stdout.strip()
        self.stop_gracefully("tacua-exp007-recreated", "pre-migration-stop")

        migration_start = time.monotonic()
        migrated = self.run_once(
            "tacua-exp007-migrate-success",
            "migration-success",
            ["migrate", "--to", "2"],
            volumes=[("tacua-exp007-state-a", "/data"), ("tacua-exp007-backups", "/backup")],
        )
        self.measurements["migration_seconds"] = round(time.monotonic() - migration_start, 4)
        migrated_checksum = migrated.stdout.strip()
        if migrated_checksum == original_checksum:
            raise RuntimeError("migration did not change the state checksum")
        self.test(
            "migration-success",
            "passed",
            {"from_schema": 1, "to_schema": 2, "before_checksum": original_checksum, "after_checksum": migrated_checksum},
        )

        failed = self.run_once(
            "tacua-exp007-migrate-failure",
            "migration-deliberate-failure",
            ["migrate", "--to", "1", "--simulate-failure"],
            volumes=[("tacua-exp007-state-a", "/data")],
            expected_failure="migration_error",
        )
        after_failure = self.state_checksum(
            "tacua-exp007-state-a", "tacua-exp007-rollback", "migration-failure-checksum"
        )
        if after_failure != migrated_checksum:
            raise RuntimeError("failed migration changed persistent state")
        self.test(
            "migration-deliberate-failure",
            "passed",
            {"exit_code": failed.returncode, "checksum_before": migrated_checksum, "checksum_after": after_failure},
        )

        restore_start = time.monotonic()
        restored = self.run_once(
            "tacua-exp007-restore-fresh",
            "rollback-from-backup",
            ["restore", "--input", "/backup/pre-migration.json", "--replace"],
            volumes=[("tacua-exp007-state-a", "/data"), ("tacua-exp007-backups", "/backup")],
        )
        self.measurements["rollback_restore_seconds"] = round(time.monotonic() - restore_start, 4)
        if restored.stdout.strip() != original_checksum:
            raise RuntimeError("rollback did not restore pre-migration state checksum")
        self.test(
            "rollback-from-pre-migration-backup",
            "passed",
            {"backup_checksum": pre_backup_checksum, "restored_state_checksum": restored.stdout.strip()},
        )

        final_backup_start = time.monotonic()
        final_backup = self.run_once(
            "tacua-exp007-backup-final",
            "backup-final",
            ["backup", "--output", "/backup/final.json"],
            volumes=[("tacua-exp007-state-a", "/data"), ("tacua-exp007-backups", "/backup")],
        )
        self.measurements["final_backup_seconds"] = round(time.monotonic() - final_backup_start, 4)
        final_backup_checksum = final_backup.stdout.strip()
        size = self.command(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                "tacua-exp007-backup-size",
                *self.docker_labels(),
                "--entrypoint",
                "/bin/stat",
                "--mount",
                "type=volume,src=tacua-exp007-backups,dst=/backup,readonly",
                IMAGE_TAG,
                "-c",
                "%s",
                "/backup/final.json",
            ],
            "backup-size",
        )
        self.created_containers.add("tacua-exp007-backup-size")
        self.measurements["final_backup_bytes"] = int(size.stdout.strip())

        self.run_once(
            "tacua-exp007-fixture-corrupt",
            "fixture-corrupt-backup",
            [
                "make-fixture",
                "--kind",
                "corrupt",
                "--input",
                "/backup/final.json",
                "--output",
                "/backup/corrupt.json",
            ],
            volumes=[("tacua-exp007-state-a", "/data"), ("tacua-exp007-backups", "/backup")],
        )
        self.run_once(
            "tacua-exp007-fixture-incompatible",
            "fixture-incompatible-backup",
            [
                "make-fixture",
                "--kind",
                "incompatible",
                "--input",
                "/backup/final.json",
                "--output",
                "/backup/incompatible.json",
            ],
            volumes=[("tacua-exp007-state-a", "/data"), ("tacua-exp007-backups", "/backup")],
        )

        # Remove every stopped container that referenced the source volume. Each
        # candidate is checked against both the exact run-created name set and
        # the experiment label before removal.
        for name in sorted(self.created_containers):
            self.safe_remove_container(name)

        # The only state volume removed here was created and labelled by this run.
        self.safe_remove_volume("tacua-exp007-state-a")
        self.create_volume("tacua-exp007-state-restored")
        fresh_restore_start = time.monotonic()
        fresh = self.run_once(
            "tacua-exp007-restore-fresh",
            "fresh-volume-restore",
            ["restore", "--input", "/backup/final.json"],
            volumes=[("tacua-exp007-state-restored", "/data"), ("tacua-exp007-backups", "/backup")],
        )
        self.measurements["fresh_volume_restore_seconds"] = round(time.monotonic() - fresh_restore_start, 4)
        fresh_checksum = fresh.stdout.strip()
        if fresh_checksum != original_checksum:
            raise RuntimeError("fresh-volume restore checksum mismatch")
        self.test(
            "backup-destroy-restore",
            "passed",
            {
                "backup_envelope_checksum": final_backup_checksum,
                "before_state_checksum": original_checksum,
                "restored_state_checksum": fresh_checksum,
                "source_volume_removed": True,
            },
        )

        corrupt_before = self.state_checksum(
            "tacua-exp007-state-restored", "tacua-exp007-corrupt-restore", "corrupt-restore-before"
        )
        corrupt = self.run_once(
            "tacua-exp007-incompatible-restore",
            "corrupt-backup-refusal",
            ["restore", "--input", "/backup/corrupt.json", "--replace"],
            volumes=[("tacua-exp007-state-restored", "/data"), ("tacua-exp007-backups", "/backup")],
            expected_failure="backup_error",
        )
        corrupt_after = self.state_checksum(
            "tacua-exp007-state-restored", "tacua-exp007-backup-pre", "corrupt-restore-after"
        )
        if corrupt_before != corrupt_after:
            raise RuntimeError("corrupt backup refusal mutated state")
        self.test(
            "corrupt-backup-refusal",
            "passed",
            {"exit_code": corrupt.returncode, "checksum_before": corrupt_before, "checksum_after": corrupt_after},
        )

        incompatible = self.run_once(
            "tacua-exp007-backup-final",
            "incompatible-backup-refusal",
            ["restore", "--input", "/backup/incompatible.json", "--replace"],
            volumes=[("tacua-exp007-state-restored", "/data"), ("tacua-exp007-backups", "/backup")],
            expected_failure="backup_error",
        )
        incompatible_after = self.state_checksum(
            "tacua-exp007-state-restored", "tacua-exp007-fixture-corrupt", "incompatible-restore-after"
        )
        if incompatible_after != corrupt_after:
            raise RuntimeError("incompatible backup refusal mutated state")
        self.test(
            "incompatible-backup-refusal",
            "passed",
            {"exit_code": incompatible.returncode, "checksum_before": corrupt_after, "checksum_after": incompatible_after},
        )

        missing_args = [
            "docker",
            "run",
            "--name",
            "tacua-exp007-config-missing",
            *self.docker_labels(),
            *self.standard_isolation(),
            IMAGE_TAG,
            "checksum",
        ]
        self.created_containers.add("tacua-exp007-config-missing")
        missing = self.expect_failure(missing_args, "missing-config", "config_error")
        invalid = self.run_once(
            "tacua-exp007-config-invalid",
            "invalid-config",
            ["checksum"],
            config_path=self.invalid_config_path,
            volumes=[("tacua-exp007-state-restored", "/data")],
            expected_failure="config_error",
        )
        self.test("explicit-configuration-failures", "passed", {"missing_exit": missing.returncode, "invalid_exit": invalid.returncode})

        permission = self.run_once(
            "tacua-exp007-volume-permission",
            "volume-permission-failure",
            ["serve"],
            extra=["--network", "none", "--tmpfs", "/data:rw,size=1m,mode=0555"],
            expected_failure="state_error",
        )
        self.test("volume-permission-failure", "passed", {"exit_code": permission.returncode, "typed_error": "state_error"})

        quota = self.run_once(
            "tacua-exp007-disk-quota",
            "disk-quota-failure",
            ["backup", "--output", "/backup/oversized.json", "--pad-bytes", "262144"],
            volumes=[("tacua-exp007-state-restored", "/data")],
            extra=["--tmpfs", "/backup:rw,size=4k,mode=0777"],
            expected_failure="backup_error",
        )
        self.test("disk-quota-failure", "passed", {"exit_code": quota.returncode, "typed_error": "backup_error"})

        owner_args = [
            "docker",
            "run",
            "-d",
            "--name",
            "tacua-exp007-port-owner",
            *self.docker_labels(),
            *self.standard_isolation(),
            *self.config_mount(),
            *self.env_args("port-owner"),
            "--mount",
            "type=volume,src=tacua-exp007-state-restored,dst=/data",
            "--publish",
            f"127.0.0.1:{PORT}:8707",
            IMAGE_TAG,
            "serve",
        ]
        self.command(owner_args, "port-owner")
        self.created_containers.add("tacua-exp007-port-owner")
        self.wait_healthy("tacua-exp007-port-owner", "port-owner")
        conflict_args = [
            "docker",
            "run",
            "-d",
            "--name",
            "tacua-exp007-port-conflict",
            *self.docker_labels(),
            *self.standard_isolation(),
            *self.config_mount(),
            *self.env_args("port-conflict"),
            "--tmpfs",
            "/data:rw,size=1m,mode=0777",
            "--publish",
            f"127.0.0.1:{PORT}:8707",
            IMAGE_TAG,
            "serve",
        ]
        self.created_containers.add("tacua-exp007-port-conflict")
        conflict = self.expect_failure(conflict_args, "port-conflict")
        self.stop_gracefully("tacua-exp007-port-owner", "port-owner-stop")
        self.test("port-conflict", "passed", {"exit_code": conflict.returncode, "host_binding": f"127.0.0.1:{PORT}"})

        final_identity = self.command(
            ["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE_TAG],
            "unchanged-image-identity",
        ).stdout.strip()
        if final_identity != self.image_id:
            raise RuntimeError("image identity changed during the local conformance run")
        self.test(
            "unchanged-local-artifact",
            "passed",
            {"initial_image_id": self.image_id, "final_image_id": final_identity},
        )

    def write_results(
        self,
        preflight: dict[str, Any],
        image_metadata: dict[str, Any],
        outcome: str,
        error: str | None,
        cleanup: dict[str, Any],
    ) -> None:
        RESULT_DIR.mkdir(parents=True, exist_ok=True)
        completed_at = utc_now()
        manifest = {
            "experiment_id": "EXP-007",
            "phase": "local-packaging-contract-smoke",
            "scope": "placeholder probe only; not a production topology",
            "run_id": self.run_id,
            "outcome": outcome,
            "error": scrub(error or "", self.token) or None,
            "started_at": preflight.get("started_at"),
            "completed_at": completed_at,
            "elapsed_seconds": round(time.monotonic() - self.started, 4),
            "preflight": preflight,
            "image": image_metadata,
            "tests": self.tests,
            "measurements": self.measurements,
            "commands": self.command_log,
            "cleanup": cleanup,
            "remote_portability": {
                "status": "blocked",
                "reason": "No remote host or image transport/registry authorization was supplied.",
                "required_input": "An approved ephemeral generic Linux/container host and secure artifact transport scope.",
                "unchanged_artifact_identity": self.image_id or None,
                "saved_artifact_sha256": self.archive_checksum or None,
            },
        }
        (RESULT_DIR / "run-manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (RESULT_DIR / "measurements.json").write_text(json.dumps(self.measurements, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (RESULT_DIR / "test-results.json").write_text(json.dumps(self.tests, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (RESULT_DIR / "image-metadata.json").write_text(json.dumps(image_metadata, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        (RESULT_DIR / "cleanup-inventory.json").write_text(json.dumps(cleanup, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def cleanup(self) -> dict[str, Any]:
        before: list[dict[str, Any]] = []
        removed: list[dict[str, Any]] = []
        for name in sorted(self.created_containers):
            label = self.ownership_label("container", name)
            before.append({"kind": "container", "name": name, "label": label, "action": "remove_if_owned"})
        for name in sorted(self.created_volumes):
            label = self.ownership_label("volume", name)
            before.append({"kind": "volume", "name": name, "label": label, "action": "remove_if_owned"})
        before.append(
            {
                "kind": "image",
                "name": IMAGE_TAG,
                "label": EXPERIMENT_LABEL if self.image_id else None,
                "action": "retain for blocked unchanged-artifact remote phase",
            }
        )
        started = time.monotonic()
        for name in sorted(self.created_containers):
            if self.safe_remove_container(name):
                removed.append({"kind": "container", "name": name})
        for name in sorted(list(self.created_volumes)):
            if self.safe_remove_volume(name):
                removed.append({"kind": "volume", "name": name})
        self.measurements["cleanup_seconds"] = round(time.monotonic() - started, 4)
        return {
            "dry_run_inventory": before,
            "removed": removed,
            "retained": [
                {
                    "kind": "image",
                    "name": IMAGE_TAG,
                    "image_id": self.image_id or None,
                    "reason": "Retained as the content-addressed artifact for a future authorized remote phase.",
                }
            ]
            if self.image_id
            else [],
        }

    def run(self) -> int:
        preflight: dict[str, Any] = {"started_at": utc_now()}
        image_metadata: dict[str, Any] = {}
        outcome = "failed"
        error: str | None = None
        try:
            preflight = self.preflight()
            image_metadata = self.build(preflight)
            self.conformance()
            if not self.tests or any(test["status"] != "passed" for test in self.tests):
                raise RuntimeError("one or more conformance cases did not pass")
            outcome = "local-phase-passed"
        except Exception as exc:  # evidence must survive any partial run
            error = f"{exc.__class__.__name__}: {exc}"
            print(error, file=sys.stderr)
        cleanup: dict[str, Any]
        try:
            cleanup = self.cleanup()
        except Exception as exc:
            cleanup = {"cleanup_error": scrub(f"{exc.__class__.__name__}: {exc}", self.token)}
            if error is None:
                error = cleanup["cleanup_error"]
                outcome = "failed"
        self.write_results(preflight, image_metadata, outcome, error, cleanup)
        try:
            shutil.rmtree(RUNTIME_DIR)
        except FileNotFoundError:
            pass
        return 0 if outcome == "local-phase-passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    return Harness().run()


if __name__ == "__main__":
    raise SystemExit(main())
