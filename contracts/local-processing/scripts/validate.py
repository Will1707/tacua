#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate inert Tacua local-processing contract documents and fixtures."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from local_processing_contract import (  # noqa: E402
    ContractError,
    canonical_json,
    load_json,
    validate_artifact,
    validate_bundle,
    validate_exchange,
    validate_fixture_corpus,
    validate_isolated_exchange,
)


def _report(status: str, code: str) -> str:
    return canonical_json(
        {
            "authority": "synthetic_contract_only",
            "code": code,
            "status": status,
        }
    )


class ContentFreeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        print(_report("invalid", "CLI_ARGUMENT_INVALID"), file=sys.stderr)
        raise SystemExit(2)


def parse_args() -> argparse.Namespace:
    parser = ContentFreeArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(
        dest="command",
        parser_class=ContentFreeArgumentParser,
        required=True,
    )

    artifact = subparsers.add_parser("artifact", help="validate one canonical wire document")
    artifact.add_argument("path", type=Path)

    exchange = subparsers.add_parser(
        "exchange", help="cross-validate one adapter input/result pair"
    )
    exchange.add_argument("input", type=Path)
    exchange.add_argument("result", type=Path)

    isolated = subparsers.add_parser(
        "isolated-exchange",
        help="cross-validate original input plus isolated-wrapper input/output",
    )
    isolated.add_argument("original_input", type=Path)
    isolated.add_argument("input", type=Path)
    isolated.add_argument("output", type=Path)

    bundle = subparsers.add_parser("bundle", help="validate one positive fixture bundle")
    bundle.add_argument("directory", type=Path)

    fixtures = subparsers.add_parser(
        "fixtures", help="validate the exact checked-in positive and negative corpus"
    )
    fixtures.add_argument("directory", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "artifact":
            validate_artifact(load_json(args.path))
        elif args.command == "exchange":
            validate_exchange(load_json(args.input), load_json(args.result))
        elif args.command == "isolated-exchange":
            validate_isolated_exchange(
                load_json(args.original_input),
                load_json(args.input),
                load_json(args.output),
            )
        elif args.command == "bundle":
            validate_bundle(args.directory)
        else:
            validate_fixture_corpus(args.directory)
    except ContractError as error:
        print(_report("invalid", error.code), file=sys.stderr)
        return 1
    except Exception:
        # This command is a content boundary. An unexpected validator failure
        # must never turn rejected transcript or processor data into a traceback.
        print(_report("invalid", "LOCAL_PROCESSING_CONTRACT_REJECTED"), file=sys.stderr)
        return 1
    print(_report("valid", "LOCAL_PROCESSING_CONTRACT_VALID"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
