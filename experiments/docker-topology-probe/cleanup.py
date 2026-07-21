#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""List or remove only the exact Docker resources owned by Tacua EXP-007."""

from __future__ import annotations

import argparse
import json
import subprocess


LABEL = "tacua-exp007"
IMAGE = "tacua-exp007-probe:0.1.0"
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
VOLUMES = ["tacua-exp007-state-a", "tacua-exp007-state-restored", "tacua-exp007-backups"]


def inspect(kind: str, name: str) -> str | None:
    if kind == "container":
        template = '{{index .Config.Labels "tacua.experiment"}}'
    elif kind == "volume":
        template = '{{index .Labels "tacua.experiment"}}'
    else:
        template = '{{index .Config.Labels "tacua.experiment"}}'
    result = subprocess.run(
        ["docker", kind, "inspect", "--format", template, name],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="remove exact labelled containers and volumes")
    parser.add_argument("--include-image", action="store_true", help="also remove the exact labelled image")
    args = parser.parse_args()
    inventory: list[dict[str, str | None]] = []
    for kind, names in (("container", CONTAINERS), ("volume", VOLUMES), ("image", [IMAGE])):
        for name in names:
            label = inspect(kind, name)
            if label is not None:
                inventory.append({"kind": kind, "name": name, "label": label})
    print(json.dumps({"mode": "execute" if args.execute else "dry-run", "resources": inventory}, indent=2))
    if not args.execute:
        return 0
    for resource in inventory:
        if resource["label"] != LABEL:
            raise SystemExit(f"refusing to remove unowned {resource['kind']} {resource['name']}")
    for resource in inventory:
        if resource["kind"] == "container":
            subprocess.run(["docker", "rm", "-f", str(resource["name"])], check=True)
    for resource in inventory:
        if resource["kind"] == "volume":
            subprocess.run(["docker", "volume", "rm", str(resource["name"])], check=True)
    if args.include_image:
        for resource in inventory:
            if resource["kind"] == "image":
                subprocess.run(["docker", "image", "rm", str(resource["name"])], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
