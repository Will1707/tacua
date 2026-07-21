#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate one protocol artifact or the synthetic lifecycle bundle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "contracts" / "runtime" / "src"))

import protocol_contract as protocol  # noqa: E402


def load(root: Path, name: str) -> dict:
    return protocol.load_json(root / name)


def validate_bundle(root: Path) -> None:
    deletion = None
    if (root / "deletion-request.json").exists() and (root / "deletion-tombstone.json").exists():
        deletion = (load(root, "deletion-request.json"), load(root, "deletion-tombstone.json"))
    protocol.validate_bundle(
        load(root, "build-identity.json"),
        load(root, "capture-scope.json"),
        load(root, "launch-exchange-request.json"),
        load(root, "launch-exchange-receipt.json"),
        [(load(root, "segment-upload-intent.json"), load(root, "segment-upload-receipt.json"))],
        [(load(root, "diagnostic-upload-request.json"), load(root, "diagnostic-upload-receipt.json"))],
        load(root, "completion-request.json"),
        load(root, "completion-receipt.json"),
        deletion,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    artifact = subparsers.add_parser("artifact", help="validate one protocol JSON artifact")
    artifact.add_argument("path", type=Path)
    bundle = subparsers.add_parser("bundle", help="validate a lifecycle fixture directory")
    bundle.add_argument("path", type=Path)
    args = parser.parse_args()
    if args.command == "artifact":
        protocol.validate(protocol.load_json(args.path))
    else:
        validate_bundle(args.path)


if __name__ == "__main__":
    main()
