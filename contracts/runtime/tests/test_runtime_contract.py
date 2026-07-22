# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_contract import (  # noqa: E402
    AUTHORITATIVE_TICKET_MEDIA_TYPE,
    AUTHORITATIVE_TICKET_VERSION,
    RUNTIME_TICKET_MEDIA_TYPE,
    RUNTIME_TICKET_VERSION,
    ContractError,
    digest_without,
    load_json,
    migrate_retired_runtime_ticket,
    seal,
    validate,
    validate_bundle,
)


POSITIVE = ROOT / "fixtures" / "positive"
NEGATIVE = ROOT / "fixtures" / "negative"


def load_bundle() -> list[dict]:
    return [load_json(POSITIVE / name) for name in ("capture.json", "diagnostics.json", "job.json", "ticket.json")]


class RuntimeContractTests(unittest.TestCase):
    def test_runtime_ticket_identity_is_distinct_and_retired_identity_is_migratable(self) -> None:
        runtime_schema = json.loads(
            (ROOT / "schemas" / "ticket-candidate.schema.json").read_text(encoding="utf-8")
        )
        authoritative_schema = json.loads(
            (ROOT.parent / "ticket-candidate" / "schemas" / "ticket-candidate.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(RUNTIME_TICKET_VERSION, runtime_schema["properties"]["contract_version"]["const"])
        self.assertEqual(RUNTIME_TICKET_MEDIA_TYPE, runtime_schema["properties"]["media_type"]["const"])
        self.assertEqual(
            AUTHORITATIVE_TICKET_VERSION,
            authoritative_schema["properties"]["contract_version"]["const"],
        )
        self.assertEqual(
            AUTHORITATIVE_TICKET_MEDIA_TYPE,
            authoritative_schema["properties"]["media_type"]["const"],
        )
        self.assertNotEqual(RUNTIME_TICKET_VERSION, AUTHORITATIVE_TICKET_VERSION)
        self.assertNotEqual(RUNTIME_TICKET_MEDIA_TYPE, AUTHORITATIVE_TICKET_MEDIA_TYPE)

        retired = copy.deepcopy(load_bundle()[3])
        retired["contract_version"] = AUTHORITATIVE_TICKET_VERSION
        retired["media_type"] = AUTHORITATIVE_TICKET_MEDIA_TYPE
        retired["candidate_digest"] = digest_without(retired, "candidate_digest")
        with self.assertRaises(ContractError) as raised:
            validate(retired)
        self.assertEqual("CONTRACT_OWNERSHIP_MISMATCH", raised.exception.code)

        migrated = migrate_retired_runtime_ticket(retired)
        validate(migrated)
        self.assertEqual(RUNTIME_TICKET_VERSION, migrated["contract_version"])
        self.assertEqual(RUNTIME_TICKET_MEDIA_TYPE, migrated["media_type"])
        self.assertEqual(retired["content"], migrated["content"])

        tampered = copy.deepcopy(retired)
        tampered["content"]["title"] = "Tampered before migration"
        with self.assertRaises(ContractError) as raised:
            migrate_retired_runtime_ticket(tampered)
        self.assertEqual("DIGEST_MISMATCH", raised.exception.code)

        authoritative_fixture = load_json(
            ROOT.parent / "ticket-candidate" / "fixtures" / "positive" / "version-1-draft.json"
        )
        with self.assertRaises(ContractError):
            migrate_retired_runtime_ticket(authoritative_fixture)

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

    def test_complete_capture_requires_narration_and_enforces_raw_retention_ceiling(self) -> None:
        capture = load_bundle()[0]
        capture["streams"]["microphone"] = "disabled"
        capture = seal(capture)
        with self.assertRaises(ContractError) as raised:
            validate(capture)
        self.assertEqual("COMPLETE_NARRATION_REQUIRED", raised.exception.code)

        capture = load_bundle()[0]
        capture["retention"]["raw_media_expires_at"] = "2026-08-21T10:00:01Z"
        capture = seal(capture)
        with self.assertRaises(ContractError) as raised:
            validate(capture)
        self.assertEqual("MAX_RAW_RETENTION_EXCEEDED", raised.exception.code)

    def test_supported_claims_require_evidence_and_ticket_ids_are_unique(self) -> None:
        ticket = load_bundle()[3]
        ticket["content"]["claims"][0]["evidence_refs"] = []
        ticket = seal(ticket)
        with self.assertRaises(ContractError) as raised:
            validate(ticket)
        self.assertEqual("SUPPORTED_CLAIM_REQUIRES_EVIDENCE", raised.exception.code)

        ticket = load_bundle()[3]
        ticket["content"]["reproduction_steps"].append(
            copy.deepcopy(ticket["content"]["reproduction_steps"][0])
        )
        ticket = seal(ticket)
        with self.assertRaises(ContractError) as raised:
            validate(ticket)
        self.assertEqual("DUPLICATE_VALUE", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
