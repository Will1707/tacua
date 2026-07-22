#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate one runtime artifact or a four-file fixture bundle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_contract import ContractError, load_json, validate, validate_bundle  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    artifact = subparsers.add_parser("artifact")
    artifact.add_argument("path", type=Path)
    bundle = subparsers.add_parser("bundle")
    bundle.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "artifact":
            validate(load_json(args.path))
        else:
            validate_bundle(*[
                load_json(args.directory / name)
                for name in ("capture.json", "diagnostics.json", "job.json", "ticket.json")
            ])
    except (ContractError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("valid structural runtime contract; this output does not grant execution authority")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
