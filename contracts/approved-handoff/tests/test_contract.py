# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import json
import subprocess
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
    MAX_SAFE_INTEGER,
    canonical_json,
    issue_execution_assertion,
    load_execution_key,
    load_json,
    load_registry_key,
    parse_source_candidate,
    project_source_candidate_ticket,
    render_markdown,
    seal_build_identity,
    seal_handoff,
    seal_execution_assertion,
    seal_execution_revocations,
    seal_registry_assertion,
    seal_trial,
    validate_build_identity,
    validate_authority,
    validate_evidence_manifest,
    validate_execution_authorization,
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
        cls.execution_assertion = load_json(POSITIVE / "execution-assertion.json", require_canonical=True)
        cls.execution_revocations = load_json(POSITIVE / "execution-revocations.json", require_canonical=True)
        cls.execution_key = load_execution_key(POSITIVE / "execution-key.synthetic.hex")
        cls.trial = load_json(POSITIVE / "agent-trial.json", require_canonical=True)
        cls.markdown = (POSITIVE / "approved-handoff.md").read_text(encoding="utf-8")

    def validate_executable(self, handoff: dict | None = None, assertion: dict | None = None) -> None:
        validate_synthetic_fixture_handoff(
            handoff or self.handoff,
            assertion or self.assertion,
            self.registry_key,
            POSITIVE / "registry-key.synthetic.hex",
            self.execution_assertion,
            self.execution_revocations,
            self.execution_key,
            POSITIVE / "execution-key.synthetic.hex",
        )

    def validate_trial_fixture(self, trial: dict) -> None:
        validate_trial(
            trial,
            self.handoff,
            self.markdown,
            registry_assertion=self.assertion,
            registry_key=self.registry_key,
            execution_assertion=self.execution_assertion,
            execution_revocations=self.execution_revocations,
            execution_key=self.execution_key,
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
            "execution-assertion.schema.json",
            "execution-revocations.schema.json",
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
        for invalid in ({"value": 1.5}, {"value": MAX_SAFE_INTEGER + 1}):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ContractError):
                    canonical_json(invalid)

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
                try:
                    candidate = mutate(self.handoff, descriptor)
                except ContractError as error:
                    self.assertEqual(descriptor["expected_error"], error.code)
                    continue
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

        extra_source = copy.deepcopy(self.assertion)
        extra_source["authorized_sources"].append(
            {
                "component": "repository",
                "source_id": "repo-unrelated-synthetic",
                "snapshot_revision": "fedcba9876543210fedcba9876543210fedcba98",
            }
        )
        extra_source["authorized_sources"].sort(
            key=lambda source: (
                source["component"],
                source["source_id"],
                source["snapshot_revision"],
            )
        )
        extra_source = seal_registry_assertion(extra_source, self.registry_key)
        cases.append((extra_source, "UNTRUSTED_EVIDENCE_SOURCE", TRUST_TIME))

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

    def test_registry_and_execution_authorities_require_distinct_key_ids_and_material(self) -> None:
        reused_key_id = copy.deepcopy(self.assertion)
        reused_key_id["execution_authority"]["key_id"] = reused_key_id["signature"]["key_id"]
        reused_key_id = seal_registry_assertion(reused_key_id, self.registry_key)
        with self.assertRaises(ContractError) as raised:
            validate_registry_assertion(
                reused_key_id,
                self.registry_key,
                self.handoff,
                at_time=TRUST_TIME,
            )
        self.assertEqual("TRUST_KEY_ID_REUSE", raised.exception.code)

        with self.assertRaises(ContractError) as raised:
            validate_handoff(
                self.handoff,
                executable=True,
                registry_assertion=self.assertion,
                registry_key=self.registry_key,
                execution_assertion=self.execution_assertion,
                execution_revocations=self.execution_revocations,
                execution_key=self.registry_key,
            )
        self.assertEqual("TRUST_KEY_MATERIAL_REUSE", raised.exception.code)

        issue_arguments = {
            "assertion_id": "execution-synthetic-separation-test",
            "instance_id": "codex-task-synthetic-separation-test",
            "nonce": "c3ludGhldGljLXNlcGFyYXRpb24tdGVzdA",
            "issued_at": TRUST_TIME,
            "lifetime_seconds": 60,
        }
        with self.assertRaises(ContractError) as raised:
            issue_execution_assertion(
                self.handoff,
                reused_key_id,
                self.registry_key,
                self.execution_key,
                **issue_arguments,
            )
        self.assertEqual("TRUST_KEY_ID_REUSE", raised.exception.code)
        with self.assertRaises(ContractError) as raised:
            issue_execution_assertion(
                self.handoff,
                self.assertion,
                self.registry_key,
                self.registry_key,
                **issue_arguments,
            )
        self.assertEqual("TRUST_KEY_MATERIAL_REUSE", raised.exception.code)

    def test_execution_issuance_authenticates_current_registry_and_structural_handoff(self) -> None:
        issue_arguments = {
            "assertion_id": "execution-synthetic-issuance-test",
            "instance_id": "codex-task-synthetic-issuance-test",
            "nonce": "c3ludGhldGljLWlzc3VhbmNlLXRlc3Q",
            "issued_at": TRUST_TIME,
            "lifetime_seconds": 60,
        }
        cases = []

        forged_signature = copy.deepcopy(self.assertion)
        forged_signature["signature"]["value"] = "hmac-sha256:" + "0" * 64
        cases.append((self.handoff, forged_signature, TRUST_TIME, "REGISTRY_SIGNATURE_MISMATCH"))

        wrong_scope = copy.deepcopy(self.assertion)
        wrong_scope["project_id"] = "project-foreign-synthetic"
        wrong_scope = seal_registry_assertion(wrong_scope, self.registry_key)
        cases.append((self.handoff, wrong_scope, TRUST_TIME, "REGISTRY_ASSERTION_SCOPE_MISMATCH"))

        cases.append(
            (
                self.handoff,
                self.assertion,
                datetime(2028, 1, 1, tzinfo=timezone.utc),
                "REGISTRY_ASSERTION_EXPIRED",
            )
        )

        malformed_handoff = copy.deepcopy(self.handoff)
        malformed_handoff["ticket"]["ticket_id"] = "ticket-forged-synthetic"
        cases.append((malformed_handoff, self.assertion, TRUST_TIME, "DIGEST_MISMATCH"))

        for handoff, registry_assertion, issued_at, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(ContractError) as raised:
                    issue_execution_assertion(
                        handoff,
                        registry_assertion,
                        self.registry_key,
                        self.execution_key,
                        **{**issue_arguments, "issued_at": issued_at},
                    )
                self.assertEqual(expected, raised.exception.code)

    def test_execution_repository_ids_bind_exactly_one_immutable_revision(self) -> None:
        for conflicting_revision in (False, True):
            build = copy.deepcopy(self.build)
            duplicate = copy.deepcopy(build["backend"]["sources"][0])
            if conflicting_revision:
                duplicate["revision"] = "fedcba9876543210fedcba9876543210fedcba98"
            build["backend"]["sources"].append(duplicate)
            build = seal_build_identity(build)
            with self.subTest(location="build", conflicting=conflicting_revision):
                with self.assertRaises(ContractError) as raised:
                    validate_build_identity(build)
                self.assertIn(
                    raised.exception.code,
                    {"DUPLICATE_REPOSITORY_ID", "SCHEMA_UNIQUE_ITEMS"},
                )

        for conflicting_revision in (False, True):
            assertion = copy.deepcopy(self.execution_assertion)
            duplicate = copy.deepcopy(assertion["repositories"][0])
            if conflicting_revision:
                duplicate["revision"] = "fedcba9876543210fedcba9876543210fedcba98"
            assertion["repositories"].append(duplicate)
            assertion["repositories"].sort(
                key=lambda item: (item["repository_id"], item["revision"])
            )
            assertion = seal_execution_assertion(assertion, self.execution_key)
            with self.subTest(location="assertion", conflicting=conflicting_revision):
                with self.assertRaises(ContractError) as raised:
                    validate_execution_authorization(
                        assertion,
                        self.execution_revocations,
                        self.execution_key,
                        self.assertion,
                        self.handoff,
                        registry_key=self.registry_key,
                        at_time=TRUST_TIME,
                    )
                self.assertIn(
                    raised.exception.code,
                    {"DUPLICATE_REPOSITORY_ID", "SCHEMA_UNIQUE_ITEMS"},
                )

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
                self.execution_assertion,
                self.execution_revocations,
                self.execution_key,
                POSITIVE / "execution-key.synthetic.hex",
            )
        self.assertEqual("SYNTHETIC_FIXTURE_IDENTITY_REQUIRED", raised.exception.code)

        with self.assertRaises(ContractError) as raised:
            validate_synthetic_fixture_handoff(
                self.handoff,
                self.assertion,
                self.registry_key,
                POSITIVE / "production-key.hex",
                self.execution_assertion,
                self.execution_revocations,
                self.execution_key,
                POSITIVE / "execution-key.synthetic.hex",
            )
        self.assertEqual("SYNTHETIC_FIXTURE_IDENTITY_REQUIRED", raised.exception.code)

    def test_codex_execution_assertion_scope_expiry_signature_and_revocation_are_required(self) -> None:
        cases = []

        wrong_build = copy.deepcopy(self.execution_assertion)
        wrong_build["build_id"] = "build-foreign-synthetic"
        wrong_build = seal_execution_assertion(wrong_build, self.execution_key)
        cases.append((wrong_build, self.execution_revocations, "EXECUTION_SCOPE_MISMATCH"))

        wrong_consumer = copy.deepcopy(self.execution_assertion)
        wrong_consumer["consumer"]["agent"] = "other_agent"
        wrong_consumer = seal_execution_assertion(wrong_consumer, self.execution_key)
        cases.append((wrong_consumer, self.execution_revocations, "SCHEMA_CONST"))

        too_long = copy.deepcopy(self.execution_assertion)
        too_long["expires_at"] = "2026-07-20T11:15:01Z"
        too_long = seal_execution_assertion(too_long, self.execution_key)
        cases.append((too_long, self.execution_revocations, "EXECUTION_WINDOW_TOO_LONG"))

        revoked = copy.deepcopy(self.execution_revocations)
        revoked["revoked_nonces"] = [self.execution_assertion["nonce"]]
        revoked = seal_execution_revocations(revoked, self.execution_key)
        cases.append((self.execution_assertion, revoked, "EXECUTION_ASSERTION_REVOKED"))

        bad_revocations = copy.deepcopy(self.execution_revocations)
        bad_revocations["revoked_assertion_ids"] = ["execution-unrelated-001"]
        cases.append((self.execution_assertion, bad_revocations, "REVOCATION_SIGNATURE_MISMATCH"))

        for assertion, revocations, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(ContractError) as raised:
                    validate_execution_authorization(
                        assertion,
                        revocations,
                        self.execution_key,
                        self.assertion,
                        self.handoff,
                        registry_key=self.registry_key,
                        at_time=TRUST_TIME,
                    )
                self.assertEqual(expected, raised.exception.code)

        forged_registry = copy.deepcopy(self.assertion)
        forged_registry["signature"]["value"] = "hmac-sha256:" + "0" * 64
        with self.assertRaises(ContractError) as raised:
            validate_execution_authorization(
                self.execution_assertion,
                self.execution_revocations,
                self.execution_key,
                forged_registry,
                self.handoff,
                registry_key=self.registry_key,
                at_time=TRUST_TIME,
            )
        self.assertEqual("REGISTRY_SIGNATURE_MISMATCH", raised.exception.code)

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

    def test_expiry_is_exclusive_for_every_execution_trust_artifact_and_trial(self) -> None:
        registry_expiry = datetime(2026, 7, 21, 10, 16, 1, tzinfo=timezone.utc)
        with self.assertRaises(ContractError) as raised:
            validate_registry_assertion(
                self.assertion,
                self.registry_key,
                self.handoff,
                at_time=registry_expiry,
            )
        self.assertEqual("REGISTRY_ASSERTION_EXPIRED", raised.exception.code)

        execution_expiry = datetime(2026, 7, 20, 11, 14, 0, tzinfo=timezone.utc)
        with self.assertRaises(ContractError) as raised:
            validate_execution_authorization(
                self.execution_assertion,
                self.execution_revocations,
                self.execution_key,
                self.assertion,
                self.handoff,
                registry_key=self.registry_key,
                at_time=execution_expiry,
            )
        self.assertEqual("EXECUTION_ASSERTION_EXPIRED", raised.exception.code)

        early_expiry_revocations = copy.deepcopy(self.execution_revocations)
        early_expiry_revocations["expires_at"] = "2026-07-20T11:01:00Z"
        early_expiry_revocations = seal_execution_revocations(
            early_expiry_revocations,
            self.execution_key,
        )
        with self.assertRaises(ContractError) as raised:
            validate_execution_authorization(
                self.execution_assertion,
                early_expiry_revocations,
                self.execution_key,
                self.assertion,
                self.handoff,
                registry_key=self.registry_key,
                at_time=datetime(2026, 7, 20, 11, 1, 0, tzinfo=timezone.utc),
            )
        self.assertEqual("REVOCATION_LIST_EXPIRED", raised.exception.code)

        trial = copy.deepcopy(self.trial)
        trial["completed_at"] = self.execution_assertion["expires_at"]
        trial["acceptance"]["decided_at"] = self.execution_assertion["expires_at"]
        trial = seal_trial(trial)
        with self.assertRaises(ContractError) as raised:
            self.validate_trial_fixture(trial)
        self.assertEqual("TRIAL_OUTLIVES_EXECUTION_AUTHORIZATION", raised.exception.code)

    def test_registry_and_issuance_reject_a_handoff_already_marked_superseded(self) -> None:
        handoff = copy.deepcopy(self.handoff)
        handoff["supersession"]["status"] = "superseded"
        handoff["supersession"]["superseded_by_handoff_digest"] = "sha256:" + "f" * 64
        handoff = seal_handoff(handoff)
        assertion = copy.deepcopy(self.assertion)
        assertion["current_handoff_digest"] = handoff["handoff_digest"]
        assertion = seal_registry_assertion(assertion, self.registry_key)

        with self.assertRaises(ContractError) as raised:
            validate_registry_assertion(
                assertion,
                self.registry_key,
                handoff,
                at_time=TRUST_TIME,
            )
        self.assertEqual("STALE_HANDOFF", raised.exception.code)
        with self.assertRaises(ContractError) as raised:
            issue_execution_assertion(
                handoff,
                assertion,
                self.registry_key,
                self.execution_key,
                assertion_id="execution-stale-test",
                instance_id="codex-stale-test",
                nonce="c3RhbGUtaGFuZG9mZi10ZXN0",
                issued_at=TRUST_TIME,
                lifetime_seconds=60,
            )
        self.assertEqual("STALE_HANDOFF", raised.exception.code)

    def test_execution_issuance_requires_an_integer_lifetime(self) -> None:
        for invalid in (True, 1.5):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ContractError) as raised:
                    issue_execution_assertion(
                        self.handoff,
                        self.assertion,
                        self.registry_key,
                        self.execution_key,
                        assertion_id="execution-lifetime-test",
                        instance_id="codex-lifetime-test",
                        nonce="aW52YWxpZC1saWZldGltZS10ZXN0",
                        issued_at=TRUST_TIME,
                        lifetime_seconds=invalid,
                    )
                self.assertEqual("INVALID_EXECUTION_LIFETIME", raised.exception.code)

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

            non_finite_path = Path(directory) / "non-finite.json"
            non_finite_path.write_text('{"value":NaN}', encoding="utf-8")
            for require_canonical in (False, True):
                with self.subTest(require_canonical=require_canonical):
                    with self.assertRaises(ContractError) as raised:
                        load_json(non_finite_path, require_canonical=require_canonical)
                    self.assertEqual("NON_FINITE_JSON_NUMBER", raised.exception.code)

            for filename, contents in (
                ("finite-float.json", '{"value":1.5}'),
                ("overflow-float.json", '{"value":1e309}'),
            ):
                float_path = Path(directory) / filename
                float_path.write_text(contents, encoding="utf-8")
                for require_canonical in (False, True):
                    with self.subTest(filename=filename, require_canonical=require_canonical):
                        with self.assertRaises(ContractError) as raised:
                            load_json(float_path, require_canonical=require_canonical)
                        self.assertEqual("FLOAT_FORBIDDEN", raised.exception.code)

            cli = ROOT / "scripts" / "handoff.py"
            commands = [
                ["validate", str(non_finite_path)],
                [
                    "validate-executable",
                    str(non_finite_path),
                    "--markdown",
                    str(POSITIVE / "approved-handoff.md"),
                    "--registry-assertion",
                    str(POSITIVE / "registry-assertion.json"),
                    "--registry-key-file",
                    str(POSITIVE / "registry-key.synthetic.hex"),
                    "--execution-assertion",
                    str(POSITIVE / "execution-assertion.json"),
                    "--execution-revocations",
                    str(POSITIVE / "execution-revocations.json"),
                    "--execution-key-file",
                    str(POSITIVE / "execution-key.synthetic.hex"),
                ],
                [
                    "issue-execution",
                    str(non_finite_path),
                    "--registry-assertion",
                    str(POSITIVE / "registry-assertion.json"),
                    "--registry-key-file",
                    str(POSITIVE / "registry-key.synthetic.hex"),
                    "--execution-key-file",
                    str(POSITIVE / "execution-key.synthetic.hex"),
                    "--assertion-id",
                    "execution-non-finite-test",
                    "--instance-id",
                    "codex-non-finite-test",
                    "--nonce",
                    "bm9uLWZpbml0ZS10ZXN0",
                ],
            ]
            for arguments in commands:
                with self.subTest(command=arguments[0]):
                    result = subprocess.run(
                        [sys.executable, "-B", str(cli), *arguments],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(1, result.returncode)
                    self.assertIn(b"NON_FINITE_JSON_NUMBER", result.stderr)
                    self.assertNotIn(b"Traceback", result.stderr)

            overflow_result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(cli),
                    "validate",
                    str(Path(directory) / "overflow-float.json"),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(1, overflow_result.returncode)
            self.assertIn(b"FLOAT_FORBIDDEN", overflow_result.stderr)
            self.assertNotIn(b"Traceback", overflow_result.stderr)

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
