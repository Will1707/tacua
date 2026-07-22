#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CLI for the candidate Tacua approved-handoff contract."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from handoff_contract import (  # noqa: E402
    ContractError,
    canonical_json_artifact,
    issue_execution_assertion,
    load_execution_key,
    load_registry_key,
    load_json,
    render_markdown,
    seal_handoff,
    seal_trial,
    validate_handoff,
    validate_markdown,
    validate_registry_assertion,
    validate_synthetic_fixture_handoff,
    validate_trial,
)


POSITIVE_FIXTURES = ROOT / "fixtures" / "positive"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate structure only; does not authorize execution")
    validate.add_argument("json", type=Path)
    validate.add_argument("--markdown", type=Path)

    executable = subparsers.add_parser(
        "validate-executable",
        help="validate canonical artifacts with current registry, execution, and revocation trust",
    )
    executable.add_argument("json", type=Path)
    executable.add_argument("--markdown", type=Path, required=True)
    executable.add_argument("--registry-assertion", type=Path, required=True)
    executable.add_argument("--registry-key-file", type=Path, required=True)
    executable.add_argument("--execution-assertion", type=Path, required=True)
    executable.add_argument("--execution-revocations", type=Path, required=True)
    executable.add_argument("--execution-key-file", type=Path, required=True)

    subparsers.add_parser(
        "validate-executable-fixture",
        help="validate only the checked-in synthetic fixture at its fixed test clock",
    )

    render = subparsers.add_parser("render", help="render deterministic Markdown to stdout")
    render.add_argument("json", type=Path)

    verify = subparsers.add_parser("verify", help="validate JSON and exact Markdown equivalence")
    verify.add_argument("json", type=Path)
    verify.add_argument("markdown", type=Path)

    trial = subparsers.add_parser("validate-trial", help="validate an agent trial against its handoff")
    trial.add_argument("trial", type=Path)
    trial.add_argument("handoff", type=Path)
    trial.add_argument("markdown", type=Path)
    trial.add_argument("--registry-assertion", type=Path, required=True)
    trial.add_argument("--registry-key-file", type=Path, required=True)
    trial.add_argument("--execution-assertion", type=Path, required=True)
    trial.add_argument("--execution-revocations", type=Path, required=True)
    trial.add_argument("--execution-key-file", type=Path, required=True)

    seal = subparsers.add_parser("seal", help="recompute nested handoff digests and emit canonical JSON")
    seal.add_argument("json", type=Path)

    seal_agent_trial = subparsers.add_parser("seal-trial", help="recompute a trial digest and emit canonical JSON")
    seal_agent_trial.add_argument("trial", type=Path)
    issue_execution = subparsers.add_parser(
        "issue-execution",
        help="locally issue one short-lived OpenAI Codex assertion from current registry trust",
    )
    issue_execution.add_argument("handoff", type=Path)
    issue_execution.add_argument("--registry-assertion", type=Path, required=True)
    issue_execution.add_argument("--registry-key-file", type=Path, required=True)
    issue_execution.add_argument("--execution-key-file", type=Path, required=True)
    issue_execution.add_argument("--assertion-id", required=True)
    issue_execution.add_argument("--instance-id", required=True)
    issue_execution.add_argument("--nonce", required=True)
    issue_execution.add_argument("--lifetime-seconds", type=int, default=900)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "validate":
            handoff = load_json(args.json)
            validate_handoff(handoff, executable=False)
            if args.markdown:
                validate_markdown(handoff, args.markdown.read_text(encoding="utf-8"))
            print("structurally valid; not trusted for execution", file=sys.stderr)
            return 0
        elif args.command == "validate-executable":
            handoff = load_json(args.json, require_canonical=True)
            assertion = load_json(args.registry_assertion, require_canonical=True)
            execution_assertion = load_json(args.execution_assertion, require_canonical=True)
            execution_revocations = load_json(args.execution_revocations, require_canonical=True)
            validate_handoff(
                handoff,
                executable=True,
                registry_assertion=assertion,
                registry_key=load_registry_key(args.registry_key_file),
                execution_assertion=execution_assertion,
                execution_revocations=execution_revocations,
                execution_key=load_execution_key(args.execution_key_file),
            )
            validate_markdown(handoff, args.markdown.read_text(encoding="utf-8"))
        elif args.command == "validate-executable-fixture":
            handoff_path = POSITIVE_FIXTURES / "approved-handoff.json"
            markdown_path = POSITIVE_FIXTURES / "approved-handoff.md"
            assertion_path = POSITIVE_FIXTURES / "registry-assertion.json"
            key_path = POSITIVE_FIXTURES / "registry-key.synthetic.hex"
            execution_assertion_path = POSITIVE_FIXTURES / "execution-assertion.json"
            execution_revocations_path = POSITIVE_FIXTURES / "execution-revocations.json"
            execution_key_path = POSITIVE_FIXTURES / "execution-key.synthetic.hex"
            handoff = load_json(handoff_path, require_canonical=True)
            assertion = load_json(assertion_path, require_canonical=True)
            execution_assertion = load_json(execution_assertion_path, require_canonical=True)
            execution_revocations = load_json(execution_revocations_path, require_canonical=True)
            validate_synthetic_fixture_handoff(
                handoff,
                assertion,
                load_registry_key(key_path),
                key_path,
                execution_assertion,
                execution_revocations,
                load_execution_key(execution_key_path),
                execution_key_path,
            )
            validate_markdown(handoff, markdown_path.read_text(encoding="utf-8"))
            print("synthetic fixture valid; never production execution authority", file=sys.stderr)
            return 0
        elif args.command == "render":
            sys.stdout.write(render_markdown(load_json(args.json)))
        elif args.command == "verify":
            validate_markdown(
                load_json(args.json, require_canonical=True),
                args.markdown.read_text(encoding="utf-8"),
            )
        elif args.command == "validate-trial":
            handoff = load_json(args.handoff, require_canonical=True)
            assertion = load_json(args.registry_assertion, require_canonical=True)
            execution_assertion = load_json(args.execution_assertion, require_canonical=True)
            execution_revocations = load_json(args.execution_revocations, require_canonical=True)
            validate_trial(
                load_json(args.trial, require_canonical=True),
                handoff,
                args.markdown.read_text(encoding="utf-8"),
                registry_assertion=assertion,
                registry_key=load_registry_key(args.registry_key_file),
                execution_assertion=execution_assertion,
                execution_revocations=execution_revocations,
                execution_key=load_execution_key(args.execution_key_file),
                json_artifact_bytes=args.handoff.read_bytes(),
            )
        elif args.command == "seal":
            sys.stdout.buffer.write(canonical_json_artifact(seal_handoff(load_json(args.json))))
        elif args.command == "seal-trial":
            sys.stdout.buffer.write(canonical_json_artifact(seal_trial(load_json(args.trial))))
        elif args.command == "issue-execution":
            handoff = load_json(args.handoff, require_canonical=True)
            assertion = load_json(args.registry_assertion, require_canonical=True)
            registry_key = load_registry_key(args.registry_key_file)
            execution_key = load_execution_key(args.execution_key_file)
            now = datetime.now(timezone.utc).replace(microsecond=0)
            validate_handoff(handoff, executable=False)
            validate_registry_assertion(
                assertion,
                registry_key,
                handoff,
                at_time=now,
            )
            sys.stdout.buffer.write(
                canonical_json_artifact(
                    issue_execution_assertion(
                        handoff,
                        assertion,
                        registry_key,
                        execution_key,
                        assertion_id=args.assertion_id,
                        instance_id=args.instance_id,
                        nonce=args.nonce,
                        issued_at=now,
                        lifetime_seconds=args.lifetime_seconds,
                    )
                )
            )
        else:  # pragma: no cover - argparse prevents this branch
            raise AssertionError(args.command)
    except (ContractError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    if args.command in {"seal", "seal-trial"}:
        print("sealed structurally; no approval or execution trust conferred", file=sys.stderr)
    elif args.command == "issue-execution":
        print("locally issued; execution still requires the registry-current signed revocation list", file=sys.stderr)
    elif args.command == "validate-executable":
        print(
            "valid against supplied trust artifacts; launcher must still reject revision rollback and consume the nonce",
            file=sys.stderr,
        )
    else:
        print("valid", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
