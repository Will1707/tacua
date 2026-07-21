# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from handoff_contract import (  # noqa: E402
    TICKET_CANDIDATE,
    ContractError,
    canonical_json,
    load_json,
    load_registry_key,
    parse_source_candidate,
    project_source_candidate_ticket,
    render_markdown,
    seal_handoff,
    seal_registry_assertion,
    seal_trial,
    validate_build_identity,
    validate_authority,
    validate_evidence_manifest,
    validate_handoff,
    validate_markdown,
    validate_registry_assertion,
    validate_synthetic_fixture_handoff,
    validate_trial,
)


POSITIVE = ROOT / "fixtures" / "positive"
NEGATIVE = ROOT / "fixtures" / "negative"
TRUST_TIME = datetime(2026, 7, 20, 11, 0, 0, tzinfo=timezone.utc)


def mutate(document: dict, descriptor: dict) -> dict:
    result = copy.deepcopy(document)
    for mutation in descriptor["mutations"]:
        target = result
        for component in mutation["path"][:-1]:
            target = target[component]
        leaf = mutation["path"][-1]
        if mutation["operation"] == "set":
            target[leaf] = mutation["value"]
        elif mutation["operation"] == "append":
            target[leaf].append(mutation["value"])
        else:  # pragma: no cover - fixtures are deliberately closed
            raise AssertionError(mutation["operation"])
    return seal_handoff(result) if descriptor["reseal"] else result


class ContractFixtureMixin:
    @classmethod
    def setUpClass(cls) -> None:
        cls.handoff_path = POSITIVE / "approved-handoff.json"
        cls.handoff = load_json(cls.handoff_path, require_canonical=True)
        cls.build = load_json(POSITIVE / "build-identity.json", require_canonical=True)
        cls.manifest = load_json(POSITIVE / "evidence-manifest.json", require_canonical=True)
        cls.source_candidate = TICKET_CANDIDATE.load_json(
            POSITIVE / "source-candidate.json"
        )
        cls.assertion = load_json(POSITIVE / "registry-assertion.json", require_canonical=True)
        cls.registry_key = load_registry_key(POSITIVE / "registry-key.synthetic.hex")
        cls.trial = load_json(POSITIVE / "agent-trial.json", require_canonical=True)
        cls.markdown = (POSITIVE / "approved-handoff.md").read_text(encoding="utf-8")

    def validate_executable(self, handoff: dict | None = None, assertion: dict | None = None) -> None:
        validate_synthetic_fixture_handoff(
            handoff or self.handoff,
            assertion or self.assertion,
            self.registry_key,
            POSITIVE / "registry-key.synthetic.hex",
        )

    def validate_trial_fixture(self, trial: dict) -> None:
        validate_trial(
            trial,
            self.handoff,
            self.markdown,
            registry_assertion=self.assertion,
            registry_key=self.registry_key,
            json_artifact_bytes=self.handoff_path.read_bytes(),
        )


class PositiveContractTests(ContractFixtureMixin, unittest.TestCase):
    def test_all_schemas_are_valid_json_and_strict_at_root(self) -> None:
        schema_names = {
            "build-identity.schema.json",
            "evidence-item.schema.json",
            "evidence-manifest.schema.json",
            "approved-handoff.schema.json",
            "agent-trial.schema.json",
            "registry-assertion.schema.json",
        }
        for name in schema_names:
            schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
            self.assertEqual("Apache-2.0", schema["$comment"].split(": ", 1)[1])
            self.assertIs(schema["additionalProperties"], False)

    def test_build_identity_and_manifest_standalone_fixtures(self) -> None:
        validate_build_identity(self.build)
        validate_evidence_manifest(self.manifest)
        validate_authority(self.handoff["authority"])
        self.assertEqual(self.build, self.handoff["build_identity"])
        self.assertEqual(self.manifest, self.handoff["evidence_manifest"])

    def test_v1_1_binds_the_exact_canonical_approved_candidate(self) -> None:
        source = self.handoff["source_candidate"]
        self.assertEqual("tacua.approved-handoff@1.1.0", self.handoff["contract_version"])
        self.assertEqual(
            "application/vnd.tacua.approved-handoff+json;version=1.1.0",
            self.handoff["media_type"],
        )
        self.assertEqual(self.source_candidate, parse_source_candidate(source))
        self.assertEqual(
            TICKET_CANDIDATE.canonical_json(self.source_candidate),
            source["canonical_json"],
        )
        self.assertFalse(source["canonical_json"].endswith("\n"))
        self.assertEqual(self.source_candidate["candidate_digest"], source["candidate_digest"])
        self.assertEqual(
            self.source_candidate["candidate_content_digest"],
            source["candidate_content_digest"],
        )
        projected = project_source_candidate_ticket(self.source_candidate)
        projected["ticket_content_digest"] = self.handoff["ticket"][
            "ticket_content_digest"
        ]
        self.assertEqual(projected, self.handoff["ticket"])

    def test_structural_validation_is_not_execution_trust(self) -> None:
        validate_handoff(self.handoff, executable=False)
        with self.assertRaises(ContractError) as raised:
            validate_handoff(self.handoff, executable=True)
        self.assertEqual("TRUST_INPUT_REQUIRED", raised.exception.code)

    def test_authenticated_synthetic_registry_assertion_enables_fixture_validation(self) -> None:
        self.validate_executable()
        self.assertEqual("approved", self.handoff["ticket"]["state"])
        self.assertTrue(self.handoff["approval"]["immutable"])

    def test_grounding_confidence_build_sdk_and_unavailable_evidence_are_explicit(self) -> None:
        self.assertEqual("ios", self.build["mobile"]["platform"])
        self.assertTrue(self.handoff["ticket"]["summary_claim_refs"])
        self.assertTrue(all(step["claim_refs"] and step["evidence_refs"] for step in self.handoff["ticket"]["reproduction"]["steps"]))
        self.assertTrue(all(claim["support"] and claim["confidence"] for claim in self.handoff["ticket"]["claims"]))
        unavailable = [item for item in self.manifest["items"] if item["availability"] == "unavailable"]
        self.assertEqual(["connector_revoked"], [item["unavailable"]["reason"] for item in unavailable])
        self.assertTrue(all(item["reference"] is None for item in unavailable))

    def test_markdown_is_exact_deterministic_equivalent(self) -> None:
        self.assertEqual(self.markdown, render_markdown(self.handoff))
        validate_markdown(self.handoff, self.markdown)
        self.assertIn("## Structural scope — not execution authority", self.markdown)
        self.assertIn("This file is not execution authorization.", self.markdown)
        self.assertIn("trusted registry assertion", self.markdown)
        self.assertIn("## Exact approved source candidate", self.markdown)
        self.assertIn(self.handoff["source_candidate"]["candidate_digest"], self.markdown)
        self.assertIn(
            self.handoff["source_candidate"]["candidate_content_digest"],
            self.markdown,
        )
        self.assertIn('data-tacua-field="source_candidate.canonical_json"', self.markdown)
        self.assertIn("## Canonical JSON", self.markdown)
        self.assertIn('{"approval":', self.markdown)
        self.assertIn('"handoff_digest":', self.markdown)
        self.assertNotIn("```", self.markdown)

    def test_agent_trial_binds_artifacts_trust_authority_and_acceptance(self) -> None:
        self.validate_trial_fixture(self.trial)
        self.assertEqual("accepted", self.trial["acceptance"]["status"])
        self.assertEqual(0, self.trial["reporter_intervention"]["active_seconds"])

    def test_canonical_json_has_sorted_keys_and_no_insignificant_space(self) -> None:
        self.assertTrue(canonical_json({"z": 1, "a": 2}).startswith('{"a":2,"z":1}'))

    def test_first_approved_export_preserves_later_candidate_version(self) -> None:
        self.assertGreater(self.handoff["ticket"]["ticket_version"], 1)
        self.assertEqual(
            self.source_candidate["candidate_version"],
            self.handoff["ticket"]["ticket_version"],
        )
        validate_handoff(self.handoff, executable=False)


class NegativeFixtureTests(ContractFixtureMixin, unittest.TestCase):
    def test_negative_handoff_fixtures(self) -> None:
        fixture_paths = sorted(
            path for path in NEGATIVE.glob("*.json") if path.name != "markdown-mismatch.json"
        )
        self.assertGreaterEqual(len(fixture_paths), 14)
        for path in fixture_paths:
            with self.subTest(path=path.name):
                descriptor = json.loads(path.read_text(encoding="utf-8"))
                candidate = mutate(self.handoff, descriptor)
                with self.assertRaises(ContractError) as raised:
                    if descriptor["expected_error"] == "STALE_HANDOFF":
                        self.validate_executable(candidate)
                    else:
                        validate_handoff(candidate, executable=False)
                self.assertEqual(descriptor["expected_error"], raised.exception.code)

    def test_markdown_mismatch_fixture(self) -> None:
        descriptor = json.loads((NEGATIVE / "markdown-mismatch.json").read_text(encoding="utf-8"))
        with self.assertRaises(ContractError) as raised:
            validate_markdown(self.handoff, self.markdown + descriptor["markdown_suffix"])
        self.assertEqual(descriptor["expected_error"], raised.exception.code)

    def test_registry_assertion_signature_scope_source_and_expiry_are_required(self) -> None:
        cases = []

        bad_signature = copy.deepcopy(self.assertion)
        bad_signature["current_handoff_digest"] = "sha256:" + "a" * 64
        cases.append((bad_signature, "REGISTRY_SIGNATURE_MISMATCH", TRUST_TIME))

        wrong_scope = copy.deepcopy(self.assertion)
        wrong_scope["project_id"] = "project-foreign-synthetic"
        wrong_scope = seal_registry_assertion(wrong_scope, self.registry_key)
        cases.append((wrong_scope, "REGISTRY_ASSERTION_SCOPE_MISMATCH", TRUST_TIME))

        missing_source = copy.deepcopy(self.assertion)
        missing_source["authorized_sources"] = missing_source["authorized_sources"][1:]
        missing_source = seal_registry_assertion(missing_source, self.registry_key)
        cases.append((missing_source, "UNTRUSTED_EVIDENCE_SOURCE", TRUST_TIME))

        long_lived = copy.deepcopy(self.assertion)
        long_lived["expires_at"] = "2026-07-22T10:16:01Z"
        long_lived = seal_registry_assertion(long_lived, self.registry_key)
        cases.append((long_lived, "ASSERTION_WINDOW_TOO_LONG", TRUST_TIME))

        cases.append((self.assertion, "REGISTRY_ASSERTION_EXPIRED", datetime(2028, 1, 1, tzinfo=timezone.utc)))

        for assertion, expected, trust_time in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(ContractError) as raised:
                    validate_registry_assertion(
                        assertion,
                        self.registry_key,
                        self.handoff,
                        at_time=trust_time,
                    )
                self.assertEqual(expected, raised.exception.code)

    def test_fixture_clock_is_restricted_and_real_executable_api_has_no_clock_override(self) -> None:
        non_synthetic = copy.deepcopy(self.assertion)
        non_synthetic["issuer_id"] = "registry-production-001"
        non_synthetic = seal_registry_assertion(non_synthetic, self.registry_key)
        with self.assertRaises(ContractError) as raised:
            validate_synthetic_fixture_handoff(
                self.handoff,
                non_synthetic,
                self.registry_key,
                POSITIVE / "registry-key.synthetic.hex",
            )
        self.assertEqual("SYNTHETIC_FIXTURE_IDENTITY_REQUIRED", raised.exception.code)

        with self.assertRaises(ContractError) as raised:
            validate_synthetic_fixture_handoff(
                self.handoff,
                self.assertion,
                self.registry_key,
                POSITIVE / "production-key.hex",
            )
        self.assertEqual("SYNTHETIC_FIXTURE_IDENTITY_REQUIRED", raised.exception.code)

        with self.assertRaises(TypeError):
            validate_handoff(
                self.handoff,
                executable=True,
                registry_assertion=self.assertion,
                registry_key=self.registry_key,
                at_time=TRUST_TIME,  # type: ignore[call-arg]
            )

    def test_seal_cannot_confer_execution_trust(self) -> None:
        forged = copy.deepcopy(self.handoff)
        forged["authority"]["allowed_repositories"].append(
            "repo-additional-synthetic"
        )
        forged = seal_handoff(forged)
        validate_handoff(forged, executable=False)
        with self.assertRaises(ContractError) as raised:
            validate_handoff(forged, executable=True)
        self.assertEqual("TRUST_INPUT_REQUIRED", raised.exception.code)

    def test_duplicate_keys_and_noncanonical_download_bytes_are_rejected(self) -> None:
        canonical = self.handoff_path.read_text(encoding="utf-8")
        duplicate = canonical.replace(
            '"contract_version":"tacua.approved-handoff@1.1.0"',
            '"contract_version":"tacua.approved-handoff@0.0.0","contract_version":"tacua.approved-handoff@1.1.0"',
            1,
        )
        pretty = json.dumps(self.handoff, ensure_ascii=False, indent=2)
        with tempfile.TemporaryDirectory() as directory:
            duplicate_path = Path(directory) / "duplicate.json"
            noncanonical_path = Path(directory) / "pretty.json"
            duplicate_path.write_text(duplicate, encoding="utf-8")
            noncanonical_path.write_text(pretty, encoding="utf-8")
            with self.assertRaises(ContractError) as raised:
                load_json(duplicate_path)
            self.assertEqual("DUPLICATE_JSON_KEY", raised.exception.code)
            with self.assertRaises(ContractError) as raised:
                load_json(noncanonical_path, require_canonical=True)
            self.assertEqual("NON_CANONICAL_JSON_ARTIFACT", raised.exception.code)

    def test_missing_source_and_old_v1_0_documents_are_rejected(self) -> None:
        missing = copy.deepcopy(self.handoff)
        del missing["source_candidate"]
        with self.assertRaises(ContractError) as raised:
            validate_handoff(missing)
        self.assertEqual("SCHEMA_REQUIRED", raised.exception.code)

        old = copy.deepcopy(self.handoff)
        old["contract_version"] = "tacua.approved-handoff@1.0.0"
        old["media_type"] = (
            "application/vnd.tacua.approved-handoff+json;version=1.0.0"
        )
        old = seal_handoff(old)
        with self.assertRaises(ContractError) as raised:
            validate_handoff(old)
        self.assertEqual("SCHEMA_CONST", raised.exception.code)

    def test_embedded_candidate_requires_strict_canonical_duplicate_free_json(self) -> None:
        cases = []
        trailing_newline = copy.deepcopy(self.handoff)
        trailing_newline["source_candidate"]["canonical_json"] += "\n"
        cases.append((trailing_newline, "SOURCE_CANDIDATE_JSON_NOT_CANONICAL"))

        duplicate = copy.deepcopy(self.handoff)
        raw = duplicate["source_candidate"]["canonical_json"]
        duplicate["source_candidate"]["canonical_json"] = raw.replace(
            '"approval":{', '"approval":null,"approval":{', 1
        )
        cases.append((duplicate, "SOURCE_CANDIDATE_DUPLICATE_KEY"))

        unsafe = copy.deepcopy(self.handoff)
        raw = unsafe["source_candidate"]["canonical_json"]
        unsafe["source_candidate"]["canonical_json"] = raw.replace(
            '"candidate_version":4', '"candidate_version":9007199254740993', 1
        )
        cases.append((unsafe, "SOURCE_CANDIDATE_UNSAFE_INTEGER"))

        for candidate, expected in cases:
            with self.subTest(expected=expected):
                candidate = seal_handoff(candidate)
                with self.assertRaises(ContractError) as raised:
                    validate_handoff(candidate)
                self.assertEqual(expected, raised.exception.code)

    def test_unprojected_source_change_changes_binding_and_tampering_fails(self) -> None:
        changed_source = copy.deepcopy(self.source_candidate)
        changed_source["transition"]["reason"] = (
            "Synthetic owner approved a distinct but still valid source snapshot."
        )
        changed_source = TICKET_CANDIDATE.seal(changed_source)
        TICKET_CANDIDATE.validate(changed_source)
        self.assertEqual(
            project_source_candidate_ticket(self.source_candidate),
            project_source_candidate_ticket(changed_source),
        )

        rebound = copy.deepcopy(self.handoff)
        rebound["source_candidate"] = {
            "contract_version": changed_source["contract_version"],
            "candidate_id": changed_source["candidate_id"],
            "candidate_version": changed_source["candidate_version"],
            "candidate_digest": changed_source["candidate_digest"],
            "candidate_content_digest": changed_source["candidate_content_digest"],
            "canonical_json": TICKET_CANDIDATE.canonical_json(changed_source),
        }
        rebound = seal_handoff(rebound)
        validate_handoff(rebound, executable=False)
        self.assertNotEqual(
            self.handoff["source_candidate"]["candidate_digest"],
            rebound["source_candidate"]["candidate_digest"],
        )
        self.assertNotEqual(
            self.handoff["ticket"]["ticket_content_digest"],
            rebound["ticket"]["ticket_content_digest"],
        )
        self.assertNotEqual(self.handoff["handoff_digest"], rebound["handoff_digest"])

        tampered = copy.deepcopy(self.handoff)
        embedded = json.loads(tampered["source_candidate"]["canonical_json"])
        embedded["transition"]["reason"] = "Tampered without resealing candidate"
        tampered["source_candidate"]["canonical_json"] = canonical_json(embedded)
        tampered = seal_handoff(tampered)
        with self.assertRaises(ContractError) as raised:
            validate_handoff(tampered)
        self.assertEqual("SOURCE_CANDIDATE_INVALID", raised.exception.code)

    def test_unknown_top_level_property_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.handoff)
        candidate["unknown_future_field"] = "must not be silently ignored"
        candidate = seal_handoff(candidate)
        with self.assertRaises(ContractError) as raised:
            validate_handoff(candidate)
        self.assertEqual("SCHEMA_ADDITIONAL_PROPERTY", raised.exception.code)

    def test_trial_tamper_cross_repository_and_false_fixed_outcomes_are_rejected(self) -> None:
        trial = copy.deepcopy(self.trial)
        trial["changes"][0]["repository_id"] = "repo-foreign-project"
        trial = seal_trial(trial)
        with self.assertRaises(ContractError) as raised:
            self.validate_trial_fixture(trial)
        self.assertEqual("TRIAL_REPOSITORY_FORBIDDEN", raised.exception.code)

        probes = [
            ("changes", [], "TRIAL_FIXED_WITHOUT_CHANGES"),
            ("tests", [], "TRIAL_FIXED_WITHOUT_TESTS"),
            ("evidence_used", [], "TRIAL_FIXED_WITHOUT_EVIDENCE"),
        ]
        for field, value, expected in probes:
            candidate = copy.deepcopy(self.trial)
            candidate[field] = value
            candidate = seal_trial(candidate)
            with self.subTest(field=field):
                with self.assertRaises(ContractError) as raised:
                    self.validate_trial_fixture(candidate)
                self.assertEqual(expected, raised.exception.code)

        reversed_time = copy.deepcopy(self.trial)
        reversed_time["started_at"] = "2026-07-20T12:00:00Z"
        reversed_time = seal_trial(reversed_time)
        with self.assertRaises(ContractError) as raised:
            self.validate_trial_fixture(reversed_time)
        self.assertEqual("TRIAL_TIME_REVERSED", raised.exception.code)

        unaccepted = copy.deepcopy(self.trial)
        unaccepted["acceptance"] = {
            "status": "pending",
            "actor_id": None,
            "decided_at": None,
            "notes": None,
        }
        unaccepted = seal_trial(unaccepted)
        with self.assertRaises(ContractError) as raised:
            self.validate_trial_fixture(unaccepted)
        self.assertEqual("TRIAL_FIXED_NOT_ACCEPTED", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
