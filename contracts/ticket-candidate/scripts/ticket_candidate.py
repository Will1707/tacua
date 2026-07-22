#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate and seal Tacua ticket-candidate artifacts without dependencies."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ticket_candidate_contract import (  # noqa: E402
    ContractError,
    canonical_json_artifact,
    load_json,
    seal,
    validate,
    validate_chain,
)
from candidate_replacement_contract import (  # noqa: E402
    validate_replacement_request,
    validate_replacement_response,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    validate_parser = commands.add_parser("validate", help="validate one immutable candidate version")
    validate_parser.add_argument("candidate", type=Path)
    chain_parser = commands.add_parser("validate-chain", help="validate a complete ordered version chain")
    chain_parser.add_argument("candidates", nargs="+", type=Path)
    replacement_request_parser = commands.add_parser(
        "validate-replacement-request",
        help="validate one atomic split/merge request body",
    )
    replacement_request_parser.add_argument("request", type=Path)
    replacement_response_parser = commands.add_parser(
        "validate-replacement-response",
        help="validate one committed split/merge response",
    )
    replacement_response_parser.add_argument("response", type=Path)
    replacement_response_parser.add_argument("--request", type=Path)
    seal_parser = commands.add_parser("seal", help="print canonical JSON with fixture/authoring digests recomputed")
    seal_parser.add_argument("candidate", type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "validate":
            value = load_json(args.candidate)
            validate(value)
            print(json.dumps({"candidate": str(args.candidate), "result": "valid", "execution_authorized": False}, sort_keys=True))
        elif args.command == "validate-chain":
            values = [load_json(path) for path in args.candidates]
            validate_chain(values)
            print(json.dumps({"versions": len(values), "result": "valid", "execution_authorized": False}, sort_keys=True))
        elif args.command == "validate-replacement-request":
            value = load_json(args.request)
            validate_replacement_request(value)
            print(
                json.dumps(
                    {
                        "operation": value["operation"],
                        "result": "valid",
                        "execution_authorized": False,
                    },
                    sort_keys=True,
                )
            )
        elif args.command == "validate-replacement-response":
            value = load_json(args.response)
            request = None if args.request is None else load_json(args.request)
            validate_replacement_response(value, request=request)
            print(
                json.dumps(
                    {
                        "operation": value["operation"]["operation"],
                        "result": "valid",
                        "execution_authorized": False,
                    },
                    sort_keys=True,
                )
            )
        else:
            value = seal(load_json(args.candidate))
            sys.stdout.buffer.write(canonical_json_artifact(value))
    except (ContractError, OSError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
