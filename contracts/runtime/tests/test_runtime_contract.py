# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_contract import ContractError, load_json, seal, validate, validate_bundle  # noqa: E402


POSITIVE = ROOT / "fixtures" / "positive"
NEGATIVE = ROOT / "fixtures" / "negative"


def load_bundle() -> list[dict]:
    return [load_json(POSITIVE / name) for name in ("capture.json", "diagnostics.json", "job.json", "ticket.json")]


class RuntimeContractTests(unittest.TestCase):
    def test_all_schemas_are_valid_json_and_all_typed_objects_are_closed(self) -> None:
        for path in sorted((ROOT / "schemas").glob("*.schema.json")):
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
            self.assertEqual("SPDX-License-Identifier: Apache-2.0", schema["$comment"])
            stack = [schema]
            while stack:
                value = stack.pop()
                if isinstance(value, dict):
                    if value.get("type") == "object":
                        self.assertIs(value.get("additionalProperties"), False, msg=f"open object in {path.name}: {value.get('title', value)}")
                    stack.extend(value.values())
                elif isinstance(value, list):
                    stack.extend(value)

    def test_positive_bundle_is_coherent_and_integrity_bound(self) -> None:
        capture, diagnostics, job, ticket = load_bundle()
        validate_bundle(capture, diagnostics, job, ticket)
        self.assertEqual(capture["manifest_digest"], job["inputs"]["capture_manifest_digest"])
        self.assertEqual(diagnostics["envelope_digest"], job["inputs"]["diagnostic_envelope_digests"][0])
        self.assertEqual(job["job_digest"], ticket["source"]["job_digest"])
        self.assertNotIn("candidate_digest", job["outputs"]["candidate_refs"][0])

    def test_fixture_exposes_truthful_gaps_unavailable_evidence_and_ticket_fields(self) -> None:
        capture, diagnostics, _, ticket = load_bundle()
        self.assertEqual("app_backgrounded", capture["gaps"][0]["reason"])
        missing = next(item for item in diagnostics["evidence"] if item["availability"] == "unavailable")
        self.assertIsNone(missing["reference"])
        self.assertIsNotNone(missing["unavailable"])
        content = ticket["content"]
        self.assertTrue(content["actual_behavior"]["evidence_refs"])
        self.assertTrue(content["expected_behavior"]["evidence_refs"])
        self.assertTrue(content["reproduction_steps"])
        self.assertTrue(content["acceptance_criteria"])
        self.assertTrue(content["uncertainty"]["items"])
        self.assertGreaterEqual(len(content["clarifications"][0]["choices"]), 2)
        self.assertEqual("human", ticket["approval"]["actor_type"])

    def test_unknown_nested_properties_are_rejected(self) -> None:
        capture = load_bundle()[0]
        capture["upload"]["signed_url"] = "forbidden"
        capture = seal(capture)
        with self.assertRaises(ContractError) as raised:
            validate(capture)
        self.assertEqual("SCHEMA_ADDITIONAL_PROPERTY", raised.exception.code)

    def test_focused_negative_fixtures(self) -> None:
        cases = json.loads((NEGATIVE / "cases.json").read_text(encoding="utf-8"))
        for descriptor in cases:
            with self.subTest(case=descriptor["name"]):
                capture, diagnostics, job, ticket = copy.deepcopy(load_bundle())
                name = descriptor["name"]
                if name == "tampered_manifest_digest":
                    capture["segments"][0]["content"]["size_bytes"] += 1
                elif name == "cross_project_bundle":
                    job["project_id"] = "project_foreign"
                    job = seal(job)
                elif name == "unavailable_evidence_with_reference":
                    diagnostics["evidence"][2]["reference"] = copy.deepcopy(diagnostics["evidence"][0]["reference"])
                    diagnostics = seal(diagnostics)
                elif name == "machine_approval":
                    ticket["approval"]["actor_type"] = "system"
                    ticket = seal(ticket)
                elif name == "incomplete_complete_upload":
                    capture["upload"]["receipts"] = []
                    capture = seal(capture)
                elif name == "unresolved_blocking_approval":
                    clarification = ticket["content"]["clarifications"][0]
                    clarification["status"] = "unresolved"
                    clarification["selected_choice_id"] = None
                    clarification["resolution_note"] = None
                    ticket = seal(ticket)
                with self.assertRaises(ContractError) as raised:
                    validate_bundle(capture, diagnostics, job, ticket)
                self.assertEqual(descriptor["expected_error"], raised.exception.code)

    def test_first_candidate_version_must_be_draft_and_unapproved(self) -> None:
        ticket = load_bundle()[3]
        ticket["candidate_version"] = 1
        ticket["previous_candidate_digest"] = None
        ticket["state"] = "approved"
        ticket = seal(ticket)
        with self.assertRaises(ContractError) as raised:
            validate(ticket)
        self.assertEqual("FIRST_VERSION_MUST_BE_DRAFT", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
