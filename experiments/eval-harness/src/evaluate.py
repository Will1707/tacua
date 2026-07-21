#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, standard-library-only scorer for Tacua evaluation fixtures."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


EVALUATOR_VERSION = "tacua-evaluator@1.0.0"
RESULT_CONTRACT = "tacua.evaluation-result@1.0.0"
COUNT_KEYS = (
    "sessions",
    "gold_issues",
    "candidates",
    "unsupported_assertions",
    "invented_assertions",
    "merged_candidates",
    "missed_gold_issues",
    "unnecessarily_split_gold_issues",
    "split_excess_candidates",
    "extra_candidates",
    "no_issue_sessions",
    "correct_no_issue_sessions",
)


class ContractError(ValueError):
    """Raised when an input violates a scorer invariant."""


def _counts() -> dict[str, int]:
    return {key: 0 for key in COUNT_KEYS}


def _unique(items: list[dict[str, Any]], key: str, context: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        value = item.get(key)
        if not isinstance(value, str) or not value:
            raise ContractError(f"{context}: missing non-empty {key}")
        if value in result:
            raise ContractError(f"{context}: duplicate {key} {value}")
        result[value] = item
    return result


def _assert_keys_equal(actual: set[str], expected: set[str], context: str) -> None:
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ContractError(f"{context}: missing={missing} extra={extra}")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ContractError(f"{path}: root must be an object")
    return value


def evaluate_documents(corpus: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    """Validate cross-document invariants and derive independent error counts."""

    if corpus.get("contract_version") != "tacua.annotation@1.0.0":
        raise ContractError("unsupported corpus contract")
    if run.get("contract_version") != "tacua.candidate-run@1.0.0":
        raise ContractError("unsupported candidate-run contract")

    corpus_ref = f"{corpus.get('corpus_id')}@{corpus.get('corpus_version')}"
    if run.get("corpus") != corpus_ref:
        raise ContractError(f"candidate run targets {run.get('corpus')}, expected {corpus_ref}")

    corpus_sessions = _unique(corpus.get("sessions", []), "session_id", "corpus sessions")
    run_sessions = _unique(run.get("sessions", []), "session_id", "candidate sessions")
    adjudications = _unique(run.get("adjudications", []), "session_id", "adjudications")
    session_ids = set(corpus_sessions)
    _assert_keys_equal(set(run_sessions), session_ids, "candidate session coverage")
    _assert_keys_equal(set(adjudications), session_ids, "adjudication coverage")

    aggregate = _counts()
    per_session: list[dict[str, Any]] = []

    for session_id in sorted(session_ids):
        session = corpus_sessions[session_id]
        run_session = run_sessions[session_id]
        adjudication = adjudications[session_id]

        evidence = _unique(session.get("evidence", []), "evidence_id", f"{session_id} evidence")
        gold_issues = _unique(session.get("gold", {}).get("issues", []), "issue_id", f"{session_id} gold")
        candidates = _unique(run_session.get("candidates", []), "candidate_id", f"{session_id} candidates")
        mappings_list = adjudication.get("candidate_mappings", [])
        mappings = _unique(mappings_list, "candidate_id", f"{session_id} mappings")
        _assert_keys_equal(set(mappings), set(candidates), f"{session_id} mapping coverage")

        history = session.get("annotation_history", [])
        if not history:
            raise ContractError(f"{session_id}: annotation history is empty")
        versions = [event.get("version") for event in history]
        if any(not isinstance(version, int) for version in versions) or versions != sorted(set(versions)):
            raise ContractError(f"{session_id}: annotation history versions must be unique and ascending")
        if adjudication.get("label_version") != versions[-1]:
            raise ContractError(
                f"{session_id}: adjudication label_version {adjudication.get('label_version')} "
                f"does not match gold version {versions[-1]}"
            )

        assertion_ids: set[str] = set()
        for candidate in candidates.values():
            for assertion in candidate.get("assertions", []):
                assertion_id = assertion.get("assertion_id")
                if not isinstance(assertion_id, str) or not assertion_id:
                    raise ContractError(f"{session_id}: assertion is missing assertion_id")
                if assertion_id in assertion_ids:
                    raise ContractError(f"{session_id}: duplicate assertion_id {assertion_id}")
                assertion_ids.add(assertion_id)
                refs = assertion.get("evidence_refs")
                if not isinstance(refs, list) or not refs:
                    raise ContractError(f"{assertion_id}: at least one provenance reference is required")
                unknown_refs = sorted(set(refs) - set(evidence))
                if unknown_refs:
                    raise ContractError(f"{assertion_id}: unknown evidence refs {unknown_refs}")

        assertion_labels_list = adjudication.get("assertion_labels", [])
        assertion_labels = _unique(assertion_labels_list, "assertion_id", f"{session_id} assertion labels")
        _assert_keys_equal(set(assertion_labels), assertion_ids, f"{session_id} assertion-label coverage")
        valid_labels = {"supported", "unsupported", "invented"}
        for assertion_id, label in assertion_labels.items():
            if label.get("label") not in valid_labels:
                raise ContractError(f"{assertion_id}: invalid assertion label {label.get('label')}")

        mapped_gold_by_candidate: dict[str, set[str]] = {}
        candidates_by_gold: dict[str, set[str]] = {issue_id: set() for issue_id in gold_issues}
        for candidate_id, mapping in mappings.items():
            mapped_ids = mapping.get("gold_issue_ids")
            if not isinstance(mapped_ids, list) or len(mapped_ids) != len(set(mapped_ids)):
                raise ContractError(f"{candidate_id}: gold_issue_ids must be a unique list")
            unknown_issue_ids = sorted(set(mapped_ids) - set(gold_issues))
            if unknown_issue_ids:
                raise ContractError(f"{candidate_id}: unknown gold issue ids {unknown_issue_ids}")
            mapped_gold_by_candidate[candidate_id] = set(mapped_ids)
            for issue_id in mapped_ids:
                candidates_by_gold[issue_id].add(candidate_id)

        merged = sorted(candidate_id for candidate_id, ids in mapped_gold_by_candidate.items() if len(ids) > 1)
        missed = sorted(issue_id for issue_id, ids in candidates_by_gold.items() if not ids)
        split = sorted(issue_id for issue_id, ids in candidates_by_gold.items() if len(ids) > 1)
        split_excess = sum(len(candidates_by_gold[issue_id]) - 1 for issue_id in split)
        extras = sorted(candidate_id for candidate_id, ids in mapped_gold_by_candidate.items() if not ids)
        unsupported = sorted(
            assertion_id for assertion_id, label in assertion_labels.items() if label["label"] == "unsupported"
        )
        invented = sorted(
            assertion_id for assertion_id, label in assertion_labels.items() if label["label"] == "invented"
        )

        no_issue = len(gold_issues) == 0
        no_issue_correct: bool | None = len(candidates) == 0 if no_issue else None
        counts = _counts()
        counts.update(
            {
                "sessions": 1,
                "gold_issues": len(gold_issues),
                "candidates": len(candidates),
                "unsupported_assertions": len(unsupported),
                "invented_assertions": len(invented),
                "merged_candidates": len(merged),
                "missed_gold_issues": len(missed),
                "unnecessarily_split_gold_issues": len(split),
                "split_excess_candidates": split_excess,
                "extra_candidates": len(extras),
                "no_issue_sessions": 1 if no_issue else 0,
                "correct_no_issue_sessions": 1 if no_issue_correct else 0,
            }
        )
        for key in COUNT_KEYS:
            aggregate[key] += counts[key]

        per_session.append(
            {
                "session_id": session_id,
                "counts": counts,
                "merged_candidate_ids": merged,
                "missed_gold_issue_ids": missed,
                "split_gold_issue_ids": split,
                "extra_candidate_ids": extras,
                "unsupported_assertion_ids": unsupported,
                "invented_assertion_ids": invented,
                "no_issue_correct": no_issue_correct,
            }
        )

    return {
        "contract_version": RESULT_CONTRACT,
        "evaluator": EVALUATOR_VERSION,
        "corpus": corpus_ref,
        "candidate_run": f"{run.get('run_id')}@{run.get('run_version')}",
        "aggregate": aggregate,
        "per_session": per_session,
        "threshold_disposition": "blocked_pending_real_sessions_human_labels_and_owner_approval",
    }


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def baseline_projection(result: dict[str, Any]) -> dict[str, Any]:
    """Return the concise, checked-in regression artifact for a full result."""

    instance_fields = {
        "unsupported_assertion_ids": "unsupported_assertion_ids",
        "invented_assertion_ids": "invented_assertion_ids",
        "merged_candidate_ids": "merged_candidate_ids",
        "missed_gold_issue_ids": "missed_gold_issue_ids",
        "split_gold_issue_ids": "split_gold_issue_ids",
        "extra_candidate_ids": "extra_candidate_ids",
    }
    instances: dict[str, list[str]] = {}
    for output_key, session_key in instance_fields.items():
        instances[output_key] = sorted(
            item
            for session in result["per_session"]
            for item in session[session_key]
        )
    return {
        "contract_version": "tacua.synthetic-baseline@1.0.0",
        "status": "synthetic_fixture_regression_only",
        "corpus": result["corpus"],
        "candidate_run": result["candidate_run"],
        "evaluator": result["evaluator"],
        "aggregate": result["aggregate"],
        "error_instances": instances,
        "threshold_disposition": result["threshold_disposition"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args(argv)

    try:
        result = evaluate_documents(load_json(args.corpus), load_json(args.candidates))
        if args.compare:
            expected = load_json(args.compare)
            calculated = baseline_projection(result) if expected.get("contract_version") == "tacua.synthetic-baseline@1.0.0" else result
            if calculated != expected:
                sys.stderr.write("evaluation does not match checked-in baseline\n")
                sys.stderr.write("calculated:\n" + canonical_json(calculated))
                sys.stderr.write("expected:\n" + canonical_json(expected))
                return 1
            sys.stdout.write(
                canonical_json(
                    {
                        "status": "ok",
                        "comparison": str(args.compare),
                        "corpus": result["corpus"],
                        "candidate_run": result["candidate_run"],
                    }
                )
            )
        else:
            sys.stdout.write(canonical_json(result))
        return 0
    except (ContractError, OSError, json.JSONDecodeError) as error:
        sys.stderr.write(f"evaluation failed: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
