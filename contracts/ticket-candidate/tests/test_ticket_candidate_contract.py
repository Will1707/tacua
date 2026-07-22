# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
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


POSITIVE = ROOT / "fixtures" / "positive"
NEGATIVE = ROOT / "fixtures" / "negative"
POSITIVE_NAMES = (
    "version-1-draft.json",
    "version-2-needs-clarification.json",
    "version-3-ready.json",
    "version-4-approved.json",
)


def chain() -> list[dict]:
    return [load_json(POSITIVE / name) for name in POSITIVE_NAMES]


def reviewer_creation(operation: str, parents: list[dict], *, actor_type: str = "human") -> dict:
    candidate = copy.deepcopy(chain()[0])
    candidate["candidate_id"] = f"candidate_{operation}_result"
    candidate["lineage"] = {
        "operation": operation,
        "parents": copy.deepcopy(parents),
    }
    candidate["transition"] = {
        "from_state": None,
        "to_state": "draft",
        "actor": {
            "actor_type": actor_type,
            "actor_id": "reviewer_owner" if actor_type == "human" else "worker_local",
        },
        "occurred_at": candidate["version_created_at"],
        "reason": f"reviewer_{operation}_candidate",
    }
    candidate["review"] = {
        "status": "in_review",
        "reviewer_action_required": True,
        "last_human_actor_id": "reviewer_owner",
        "last_reviewed_at": candidate["version_created_at"],
        "notes": [],
    }
    return seal(candidate)


class TicketCandidateContractTests(unittest.TestCase):
    def test_contract_identity_has_one_schema_owner(self) -> None:
        authoritative = json.loads(
            (ROOT / "schemas" / "ticket-candidate.schema.json").read_text(encoding="utf-8")
        )
        runtime_prototype = json.loads(
            (ROOT.parent / "runtime" / "schemas" / "ticket-candidate.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            "tacua.ticket-candidate@1.0.0",
            authoritative["properties"]["contract_version"]["const"],
        )
        self.assertEqual(
            "application/vnd.tacua.ticket-candidate+json;version=1.0.0",
            authoritative["properties"]["media_type"]["const"],
        )
        self.assertNotEqual(
            authoritative["properties"]["contract_version"]["const"],
            runtime_prototype["properties"]["contract_version"]["const"],
        )
        self.assertNotEqual(
            authoritative["properties"]["media_type"]["const"],
            runtime_prototype["properties"]["media_type"]["const"],
        )
        runtime_fixture = load_json(
            ROOT.parent / "runtime" / "fixtures" / "positive" / "ticket.json"
        )
        with self.assertRaises(ContractError) as raised:
            validate(runtime_fixture)
        self.assertEqual("UNSUPPORTED_VERSION", raised.exception.code)

    def test_all_typed_schema_objects_are_closed(self) -> None:
        for path in sorted((ROOT / "schemas").glob("*.schema.json")):
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
            self.assertEqual("SPDX-License-Identifier: Apache-2.0", schema["$comment"])
            stack = [schema]
            while stack:
                value = stack.pop()
                if isinstance(value, dict):
                    if value.get("type") == "object":
                        self.assertIs(value.get("additionalProperties"), False, msg=f"open object in {path}: {value}")
                    stack.extend(value.values())
                elif isinstance(value, list):
                    stack.extend(value)

    def test_positive_immutable_version_chain(self) -> None:
        candidates = chain()
        validate_chain(candidates)
        self.assertEqual([1, 2, 3, 4], [item["candidate_version"] for item in candidates])
        self.assertEqual(
            ["draft", "needs_clarification", "ready_for_review", "approved"],
            [item["state"] for item in candidates],
        )
        for previous, current in zip(candidates, candidates[1:]):
            self.assertEqual(previous["candidate_digest"], current["previous_candidate_digest"])
            self.assertEqual(previous["candidate_digest"], current["lineage"]["parents"][0]["candidate_digest"])

    def test_approval_binds_reviewed_version_content_manifest_and_exact_evidence(self) -> None:
        _, _, ready, approved = chain()
        approval = approved["approval"]
        self.assertEqual(ready["candidate_version"], approval["reviewed_candidate_version"])
        self.assertEqual(ready["candidate_digest"], approval["reviewed_candidate_digest"])
        self.assertEqual(ready["candidate_content_digest"], approved["candidate_content_digest"])
        self.assertEqual(approved["candidate_content_digest"], approval["candidate_content_digest"])
        self.assertEqual(approved["evidence_manifest"]["manifest_digest"], approval["evidence_manifest_digest"])
        self.assertEqual(
            {
                "evidence_keyframe_001",
                "evidence_repository_001",
                "evidence_route_001",
                "evidence_transcript_001",
            },
            set(approval["authorized_evidence_ids"]),
        )
        self.assertTrue(approval["immutable"])

    def test_visual_choices_are_bounded_and_resolution_is_human(self) -> None:
        _, needs, ready, _ = chain()
        unresolved = needs["content"]["clarifications"][0]
        resolved = ready["content"]["clarifications"][0]
        self.assertEqual("evidence_thumbnail", unresolved["choices"][0]["presentation"]["kind"])
        self.assertEqual("text", unresolved["choices"][1]["presentation"]["kind"])
        self.assertEqual("choice_use_approved", resolved["selected_choice_id"])
        self.assertEqual("human", ready["transition"]["actor"]["actor_type"])

    def test_split_and_merge_creation_lineage_is_human_and_bounded(self) -> None:
        source = chain()[2]
        source_ref = {
            "candidate_id": source["candidate_id"],
            "candidate_version": source["candidate_version"],
            "candidate_digest": source["candidate_digest"],
        }
        other_ref = {
            "candidate_id": "candidate_other_issue",
            "candidate_version": 2,
            "candidate_digest": "sha256:" + "c" * 64,
        }

        split = reviewer_creation("split", [source_ref])
        merged = reviewer_creation("merged", [source_ref, other_ref])
        validate_chain([split])
        validate_chain([merged])
        self.assertEqual("human", split["transition"]["actor"]["actor_type"])
        self.assertEqual(2, len(merged["lineage"]["parents"]))

        for operation, parents in (
            ("split", []),
            ("split", [source_ref, other_ref]),
            ("merged", [source_ref]),
            ("merged", [source_ref] * 17),
        ):
            with self.subTest(operation=operation, parent_count=len(parents)):
                invalid = reviewer_creation(operation, parents)
                with self.assertRaises(ContractError):
                    validate(invalid)

        duplicate_merge = reviewer_creation("merged", [source_ref, source_ref])
        with self.assertRaises(ContractError):
            validate(duplicate_merge)

    def test_split_and_merge_creation_reject_machine_actors(self) -> None:
        source = chain()[2]
        source_ref = {
            "candidate_id": source["candidate_id"],
            "candidate_version": source["candidate_version"],
            "candidate_digest": source["candidate_digest"],
        }
        other_ref = {
            "candidate_id": "candidate_other_issue",
            "candidate_version": 2,
            "candidate_digest": "sha256:" + "c" * 64,
        }
        for operation, parents in (
            ("split", [source_ref]),
            ("merged", [source_ref, other_ref]),
        ):
            with self.subTest(operation=operation):
                machine_created = reviewer_creation(
                    operation,
                    parents,
                    actor_type="system",
                )
                with self.assertRaises(ContractError) as raised:
                    validate(machine_created)
                self.assertEqual("HUMAN_TRANSITION_REQUIRED", raised.exception.code)

    def test_all_checked_negative_fixtures_fail_with_stable_codes(self) -> None:
        descriptors = json.loads((NEGATIVE / "expected.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(descriptors), 8)
        for descriptor in descriptors:
            with self.subTest(file=descriptor["file"]):
                value = load_json(NEGATIVE / descriptor["file"])
                with self.assertRaises(ContractError) as raised:
                    validate(value)
                self.assertEqual(descriptor["expected_error"], raised.exception.code)

    def test_unknown_evidence_and_claim_references_are_rejected(self) -> None:
        ready = chain()[2]
        ready["content"]["actual_behavior"]["evidence_refs"] = ["evidence_missing"]
        ready = seal(ready)
        with self.assertRaises(ContractError) as raised:
            validate(ready)
        self.assertEqual("UNKNOWN_EVIDENCE_REFERENCE", raised.exception.code)

        ready = chain()[2]
        ready["content"]["actual_behavior"]["claim_refs"] = ["claim_missing"]
        ready = seal(ready)
        with self.assertRaises(ContractError) as raised:
            validate(ready)
        self.assertEqual("UNKNOWN_CLAIM_REFERENCE", raised.exception.code)

    def test_approval_cannot_silently_edit_reviewed_content(self) -> None:
        candidates = chain()
        approved = copy.deepcopy(candidates[-1])
        approved["content"]["title"] = "Changed while approving"
        approved = seal(approved)
        candidates[-1] = approved
        with self.assertRaises(ContractError) as raised:
            validate_chain(candidates)
        self.assertEqual("TERMINAL_CONTENT_CHANGED", raised.exception.code)

    def test_chain_rejects_wrong_predecessor_and_state(self) -> None:
        candidates = chain()
        candidates[2]["previous_candidate_digest"] = "sha256:" + "f" * 64
        candidates[2]["lineage"]["parents"][0]["candidate_digest"] = "sha256:" + "f" * 64
        candidates[2] = seal(candidates[2])
        with self.assertRaises(ContractError) as raised:
            validate_chain(candidates)
        self.assertEqual("VERSION_CHAIN_MISMATCH", raised.exception.code)

        candidates = chain()
        candidates[2]["transition"]["from_state"] = "draft"
        candidates[2] = seal(candidates[2])
        with self.assertRaises(ContractError) as raised:
            validate_chain(candidates)
        self.assertEqual("STATE_CHAIN_MISMATCH", raised.exception.code)

    def test_rejection_and_reopen_remain_human_versioned_transitions(self) -> None:
        candidates = chain()[:3]
        ready = candidates[-1]
        rejected = copy.deepcopy(ready)
        rejected["candidate_version"] = 4
        rejected["previous_candidate_digest"] = ready["candidate_digest"]
        rejected["state"] = "rejected"
        rejected["version_created_at"] = "2026-07-21T10:04:00Z"
        rejected["lineage"] = {
            "operation": "rejected",
            "parents": [{
                "candidate_id": ready["candidate_id"],
                "candidate_version": ready["candidate_version"],
                "candidate_digest": ready["candidate_digest"],
            }],
        }
        rejected["transition"] = {
            "from_state": "ready_for_review",
            "to_state": "rejected",
            "actor": {"actor_type": "human", "actor_id": "reviewer_owner"},
            "occurred_at": "2026-07-21T10:04:00Z",
            "reason": "reviewer_rejected_candidate",
        }
        rejected["review"]["reviewer_action_required"] = False
        rejected["review"]["last_reviewed_at"] = "2026-07-21T10:04:00Z"
        rejected["approval"] = None
        rejected["rejection"] = {
            "actor_type": "human",
            "actor_id": "reviewer_owner",
            "rejected_at": "2026-07-21T10:04:00Z",
            "reviewed_candidate_version": 3,
            "reviewed_candidate_digest": ready["candidate_digest"],
            "rejected_candidate_version": 4,
            "candidate_content_digest": ready["candidate_content_digest"],
            "reason": "The observed copy is intentional for this build.",
            "immutable": True,
        }
        rejected = seal(rejected)
        validate_chain([*candidates, rejected])

        reopened = copy.deepcopy(rejected)
        reopened["candidate_version"] = 5
        reopened["previous_candidate_digest"] = rejected["candidate_digest"]
        reopened["state"] = "draft"
        reopened["version_created_at"] = "2026-07-21T10:05:00Z"
        reopened["lineage"] = {
            "operation": "reopened",
            "parents": [{
                "candidate_id": rejected["candidate_id"],
                "candidate_version": rejected["candidate_version"],
                "candidate_digest": rejected["candidate_digest"],
            }],
        }
        reopened["transition"] = {
            "from_state": "rejected",
            "to_state": "draft",
            "actor": {"actor_type": "human", "actor_id": "reviewer_owner"},
            "occurred_at": "2026-07-21T10:05:00Z",
            "reason": "reviewer_reopened_candidate",
        }
        reopened["review"]["status"] = "in_review"
        reopened["review"]["reviewer_action_required"] = True
        reopened["review"]["last_reviewed_at"] = "2026-07-21T10:05:00Z"
        reopened["approval"] = None
        reopened["rejection"] = None
        reopened = seal(reopened)
        validate_chain([*candidates, rejected, reopened])

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"candidate_id":"one","candidate_id":"two"}\n', encoding="utf-8")
            with self.assertRaises(ContractError) as raised:
                load_json(path)
            self.assertEqual("DUPLICATE_JSON_KEY", raised.exception.code)

    def test_nul_strings_are_rejected_before_handoff_projection(self) -> None:
        candidate = copy.deepcopy(chain()[0])
        candidate["content"]["title"] = "invalid\x00title"
        candidate = seal(candidate)
        with self.assertRaises(ContractError) as raised:
            validate(candidate)
        self.assertEqual("CONTROL_CHARACTER", raised.exception.code)

    def test_cli_validates_chain_and_never_claims_execution_authority(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "ticket_candidate.py"),
                "validate-chain",
                *(str(POSITIVE / name) for name in POSITIVE_NAMES),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        output = json.loads(result.stdout)
        self.assertEqual("valid", output["result"])
        self.assertFalse(output["execution_authorized"])

    def test_fixture_regeneration_is_canonical_and_reproducible(self) -> None:
        before = {path: path.read_bytes() for path in ROOT.glob("fixtures/**/*.json")}
        subprocess.run([sys.executable, str(ROOT / "scripts" / "regenerate_fixtures.py")], check=True)
        after = {path: path.read_bytes() for path in ROOT.glob("fixtures/**/*.json")}
        self.assertEqual(before, after)
        for payload in after.values():
            value = json.loads(payload)
            self.assertEqual(canonical_json_artifact(value), payload)


if __name__ == "__main__":
    unittest.main()
