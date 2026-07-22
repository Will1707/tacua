#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed verifier for a resolved compose.processor.yaml document."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


IMAGE_RE = re.compile(r"^[^\s@]+@sha256:[a-f0-9]{64}$")
SERVICE = "private-pilot-processor"
INPUT_TARGET = "/tacua-private-payload/input/input.json"
MODEL_TARGET = "/tacua-private-payload/model/model"


class ProfileError(ValueError):
    pass


def _require(condition: bool, detail: str) -> None:
    if not condition:
        raise ProfileError(detail)


def _bytes(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        match = re.fullmatch(r"([0-9]+)([bkmg]?)", value.lower())
        if match:
            multipliers = {"": 1, "b": 1, "k": 1024, "m": 1024**2, "g": 1024**3}
            return int(match.group(1)) * multipliers[match.group(2)]
    raise ProfileError("resource byte value is invalid")


def validate_profile(compose: dict[str, Any]) -> None:
    _require(isinstance(compose, dict), "resolved Compose document must be an object")
    _require(set(compose) <= {"name", "services"}, "top-level networks, volumes, secrets and configs are forbidden")
    services = compose.get("services")
    _require(isinstance(services, dict) and set(services) == {SERVICE}, "processor profile must resolve to one service")
    service = services[SERVICE]
    _require(isinstance(service, dict), "processor service is invalid")
    expected_service_fields = {
        "cap_drop",
        "command",
        "cpus",
        "entrypoint",
        "environment",
        "image",
        "init",
        "ipc",
        "labels",
        "logging",
        "mem_limit",
        "memswap_limit",
        "network_mode",
        "pids_limit",
        "profiles",
        "pull_policy",
        "read_only",
        "restart",
        "security_opt",
        "tmpfs",
        "ulimits",
        "user",
    }
    _require(set(service) == expected_service_fields, "processor service contains an omitted or extra host/container mode")
    _require(service.get("profiles") == ["private-pilot"], "private-pilot profile is required")
    _require(isinstance(service.get("image"), str) and IMAGE_RE.fullmatch(service["image"]), "image must be digest pinned")
    _require(service.get("pull_policy") == "never", "processor image must be preloaded; pulling is forbidden")
    _require(service.get("init") is True, "container init is required for child reaping")
    _require(service.get("user") == "10002:10002", "processor must use its dedicated UID/GID")
    _require(service.get("network_mode") == "none" and "networks" not in service, "processor network must be none")
    _require(service.get("ipc") == "none", "processor IPC namespace must be isolated")
    _require(service.get("read_only") is True, "processor root filesystem must be read-only")
    _require(service.get("privileged", False) is False, "privileged processor is forbidden")
    _require(service.get("cap_drop") == ["ALL"], "all Linux capabilities must be dropped")
    _require(service.get("security_opt") == ["no-new-privileges:true"], "no-new-privileges is required")
    _require(not service.get("devices"), "host devices are forbidden")
    _require(not service.get("secrets") and not service.get("configs"), "secrets and configs are forbidden")
    _require(int(service.get("pids_limit", 0)) == 64, "PID limit must be exactly 64")
    _require(float(service.get("cpus", 0)) == 2.0, "CPU limit must be exactly 2.0")
    _require(_bytes(service.get("mem_limit")) == 4 * 1024**3, "memory limit must be exactly 4 GiB")
    _require(_bytes(service.get("memswap_limit")) == 4 * 1024**3, "swap must not exceed the memory limit")
    _require(service.get("logging", {}).get("driver") == "none", "processor logs must not retain evidence")
    _require(service.get("restart") in {"no", "none", False}, "processor must never restart automatically")
    _require(
        service.get("ulimits") == {"nofile": {"soft": 1024, "hard": 1024}},
        "file-descriptor ceiling must be exactly 1,024",
    )
    _require(
        service.get("labels")
        == {
            "com.tacua.max-container-runtime-seconds": "150",
            "com.tacua.max-runner-seconds": "210",
            "com.tacua.private-pilot-processor": "true",
            "com.tacua.runner-contract": "tacua.isolated-processing-command@1.0.0",
            "com.tacua.runner-role": "processor",
        },
        "closed private-pilot, contract, role, container and whole-runner labels are required",
    )

    environment = service.get("environment")
    _require(isinstance(environment, dict), "closed minimal environment is required")
    _require(set(environment) == {"LANG", "LC_ALL", "TACUA_PROCESSOR_MODEL_ID"}, "unexpected environment variable")
    _require(environment["LANG"] == "C.UTF-8" and environment["LC_ALL"] == "C.UTF-8", "fixed locale is required")
    _require(bool(environment["TACUA_PROCESSOR_MODEL_ID"]), "operator-selected model ID is required")

    _require(
        "volumes" not in service,
        "static mounts are forbidden; the trusted runner creates a randomized carrier/payload volume transaction",
    )

    tmpfs = service.get("tmpfs")
    _require(isinstance(tmpfs, list) and len(tmpfs) == 1, "exactly one bounded scratch tmpfs mount is required")
    _require(
        set(tmpfs)
        == {
            "/tmp:rw,nosuid,nodev,noexec,size=268435456,uid=10002,gid=10002,mode=0700",
        },
        "tmpfs paths, bounds, identity and hardening options must match exactly",
    )

    entrypoint = service.get("entrypoint")
    _require(isinstance(entrypoint, list) and len(entrypoint) == 1, "one explicit entrypoint is required")
    _require(isinstance(entrypoint[0], str) and entrypoint[0].startswith("/"), "entrypoint must be an absolute operator selection")
    _require(
        service.get("command")
        == [
            "--input",
            INPUT_TARGET,
            "--model",
            MODEL_TARGET,
        ],
        "command must be the exact shell-free input/model vector; output is the attached canonical stdout envelope",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compose_json", type=Path)
    args = parser.parse_args()
    try:
        document = json.loads(args.compose_json.read_text(encoding="utf-8"))
        validate_profile(document)
    except (OSError, UnicodeError, json.JSONDecodeError, ProfileError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print("isolated private-pilot processor profile valid", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
