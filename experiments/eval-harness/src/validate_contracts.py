#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate checked-in Tacua synthetic fixtures without third-party packages."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from evaluate import ContractError, baseline_projection, evaluate_documents, load_json
from summarize_timing import TimingError, load_events, summarize


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "corpus" / "EVAL-001.v1.0.0.json"
RUN_PATH = ROOT / "fixtures" / "candidates" / "FIXED-SYNTHETIC-CANDIDATES.v1.0.0.json"
HANDOFF_PATH = ROOT / "fixtures" / "handoff" / "HANDOFF-SYN-001.v1.0.0.json"
EVIDENCE_PATH = ROOT / "fixtures" / "evidence" / "ABLATION-SYN-001.v1.0.0.json"
TIMING_PATH = ROOT / "fixtures" / "timing" / "example-events.v1.0.0.jsonl"
BASELINE_PATH = ROOT / "fixtures" / "baselines" / "SYNTHETIC-BASELINE.v1.0.0.json"
SCHEMA_PATHS = sorted((ROOT / "schemas").glob("*.schema.json"))

REQUIRED_FAMILIES = {
    "zero_issues",
    "one_issue",
    "many_issues",
    "delayed_reference",
    "topic_return",
    "self_correction",
    "ambiguous_intent",
    "accent",
    "noise",
    "redaction_gap",
    "crash",
    "recording_gap",
    "similar_symptoms",
    "merge_trap",
    "repeated_description",
    "split_trap",
    "connector_unavailable",
    "adversarial_speech",
    "adversarial_ui",
    "adversarial_log",
    "adversarial_source",
}
SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def validate() -> dict[str, int]:
    for schema_path in SCHEMA_PATHS:
        schema = load_json(schema_path)
        require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", f"{schema_path}: wrong draft")
        require(isinstance(schema.get("$id"), str), f"{schema_path}: missing $id")

    corpus = load_json(CORPUS_PATH)
    run = load_json(RUN_PATH)
    handoff = load_json(HANDOFF_PATH)
    evidence_manifest = load_json(EVIDENCE_PATH)
    baseline = load_json(BASELINE_PATH)
    result = evaluate_documents(corpus, run)
    require(baseline_projection(result) == baseline, "checked synthetic baseline does not match evaluator output")

    require(corpus.get("status") == "synthetic_only", "corpus must remain synthetic_only")
    require(all(session.get("synthetic") is True for session in corpus["sessions"]), "all sessions must be synthetic")
    require(
        all(session.get("gold", {}).get("approval_status") == "synthetic_only" for session in corpus["sessions"]),
        "synthetic labels must not claim human approval",
    )
    found_families = {family for session in corpus["sessions"] for family in session.get("families", [])}
    missing_families = sorted(REQUIRED_FAMILIES - found_families)
    require(not missing_families, f"corpus coverage missing families: {missing_families}")

    for session in corpus["sessions"]:
        evidence_ids = {item["evidence_id"] for item in session["evidence"]}
        for item in session["evidence"]:
            require(item["start_ms"] <= item["end_ms"], f"{item['evidence_id']}: reversed window")
            require(item.get("trust") == "untrusted_evidence", f"{item['evidence_id']}: wrong trust boundary")
        for issue in session["gold"]["issues"]:
            require(issue["boundary"]["start_ms"] <= issue["boundary"]["end_ms"], f"{issue['issue_id']}: reversed boundary")
            unknown = sorted(set(issue["evidence_refs"]) - evidence_ids)
            require(not unknown, f"{issue['issue_id']}: unknown evidence refs {unknown}")

    require(handoff.get("contract_version") == "tacua.handoff-concept@1.0.0", "wrong handoff contract")
    require(handoff.get("status") == "synthetic_concept_fixture", "handoff must remain synthetic")
    authority = handoff.get("authority", {})
    require(authority.get("external_writes") is False, "handoff may not authorize external writes")
    require(authority.get("merge") is False and authority.get("deploy") is False, "handoff may not authorize merge/deploy")
    require(evidence_manifest.get("contract_version") == "tacua.evidence-manifest@1.0.0", "wrong evidence-manifest contract")
    require(
        all(item.get("authorization") in {"synthetic", "blocked"} for item in evidence_manifest.get("items", [])),
        "synthetic ablation manifest may not claim real approval",
    )
    require(run.get("producer", {}).get("network_used") is False, "fixed candidate fixture must not use network")
    require(run.get("configuration", {}).get("model_id") == "none", "fixed candidate fixture must not invoke a model")

    timing = summarize(load_events(TIMING_PATH))
    require(timing["sessions"][0]["active_ms"] == 21000, "example active-time total changed")

    scan_paths = [CORPUS_PATH, RUN_PATH, HANDOFF_PATH, EVIDENCE_PATH, TIMING_PATH]
    for path in scan_paths:
        text = path.read_text(encoding="utf-8")
        for pattern in SECRET_PATTERNS:
            require(pattern.search(text) is None, f"possible secret in {path}: {pattern.pattern}")

    return {
        "schemas": len(SCHEMA_PATHS),
        "sessions": len(corpus["sessions"]),
        "gold_issues": result["aggregate"]["gold_issues"],
        "candidate_fixtures": result["aggregate"]["candidates"],
        "coverage_families": len(found_families),
        "timing_sessions": len(timing["sessions"]),
    }


def main() -> int:
    try:
        summary = validate()
        print(json.dumps({"status": "ok", **summary}, indent=2, sort_keys=True))
        return 0
    except (ContractError, TimingError, OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        sys.stderr.write(f"validation failed: {error}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
