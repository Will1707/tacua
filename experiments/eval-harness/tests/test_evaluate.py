# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from evaluate import ContractError, evaluate_documents  # noqa: E402


class EvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = json.loads((ROOT / "corpus" / "EVAL-001.v1.0.0.json").read_text(encoding="utf-8"))
        cls.candidate_run = json.loads(
            (ROOT / "fixtures" / "candidates" / "FIXED-SYNTHETIC-CANDIDATES.v1.0.0.json").read_text(
                encoding="utf-8"
            )
        )

    def test_fixed_baseline_reports_classes_separately(self) -> None:
        aggregate = evaluate_documents(self.corpus, self.candidate_run)["aggregate"]
        self.assertEqual(
            aggregate,
            {
                "sessions": 16,
                "gold_issues": 16,
                "candidates": 16,
                "unsupported_assertions": 4,
                "invented_assertions": 3,
                "merged_candidates": 2,
                "missed_gold_issues": 2,
                "unnecessarily_split_gold_issues": 1,
                "split_excess_candidates": 1,
                "extra_candidates": 3,
                "no_issue_sessions": 3,
                "correct_no_issue_sessions": 1,
            },
        )

    def test_empty_output_misses_every_issue_but_handles_no_issue_sessions(self) -> None:
        run = copy.deepcopy(self.candidate_run)
        for session in run["sessions"]:
            session["candidates"] = []
            session["clarifications"] = []
        for adjudication in run["adjudications"]:
            adjudication["candidate_mappings"] = []
            adjudication["assertion_labels"] = []
        aggregate = evaluate_documents(self.corpus, run)["aggregate"]
        self.assertEqual(aggregate["missed_gold_issues"], 16)
        self.assertEqual(aggregate["extra_candidates"], 0)
        self.assertEqual(aggregate["correct_no_issue_sessions"], 3)

    def test_merge_is_not_collapsed_into_miss(self) -> None:
        result = evaluate_documents(self.corpus, self.candidate_run)
        session = next(item for item in result["per_session"] if item["session_id"] == "SYN-013")
        self.assertEqual(session["merged_candidate_ids"], ["S013-C1"])
        self.assertEqual(session["missed_gold_issue_ids"], [])

    def test_split_is_not_counted_as_extra(self) -> None:
        result = evaluate_documents(self.corpus, self.candidate_run)
        session = next(item for item in result["per_session"] if item["session_id"] == "SYN-014")
        self.assertEqual(session["split_gold_issue_ids"], ["S014-I1"])
        self.assertEqual(session["counts"]["split_excess_candidates"], 1)
        self.assertEqual(session["extra_candidate_ids"], [])

    def test_unknown_gold_mapping_is_rejected(self) -> None:
        run = copy.deepcopy(self.candidate_run)
        adjudication = next(item for item in run["adjudications"] if item["session_id"] == "SYN-001")
        adjudication["candidate_mappings"][0]["gold_issue_ids"] = ["S001-DOES-NOT-EXIST"]
        with self.assertRaisesRegex(ContractError, "unknown gold issue ids"):
            evaluate_documents(self.corpus, run)

    def test_missing_provenance_is_rejected(self) -> None:
        run = copy.deepcopy(self.candidate_run)
        session = next(item for item in run["sessions"] if item["session_id"] == "SYN-001")
        session["candidates"][0]["assertions"][0]["evidence_refs"] = []
        with self.assertRaisesRegex(ContractError, "provenance"):
            evaluate_documents(self.corpus, run)

    def test_stale_gold_label_version_is_rejected(self) -> None:
        run = copy.deepcopy(self.candidate_run)
        adjudication = next(item for item in run["adjudications"] if item["session_id"] == "SYN-004")
        adjudication["label_version"] = 1
        with self.assertRaisesRegex(ContractError, "does not match gold version"):
            evaluate_documents(self.corpus, run)

    def test_duplicate_candidate_is_rejected(self) -> None:
        run = copy.deepcopy(self.candidate_run)
        session = next(item for item in run["sessions"] if item["session_id"] == "SYN-014")
        session["candidates"][1]["candidate_id"] = "S014-C1"
        with self.assertRaisesRegex(ContractError, "duplicate candidate_id"):
            evaluate_documents(self.corpus, run)

    def test_hostile_text_is_inert_and_scored(self) -> None:
        result = evaluate_documents(self.corpus, self.candidate_run)
        speech = next(item for item in result["per_session"] if item["session_id"] == "SYN-009")
        self.assertEqual(speech["extra_candidate_ids"], ["S009-C1"])
        self.assertEqual(speech["invented_assertion_ids"], ["S009-C1-A1"])


if __name__ == "__main__":
    unittest.main()
