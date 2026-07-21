# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE = REPOSITORY_ROOT / "services" / "backend" / "src"
sys.path.insert(0, str(SOURCE))

from tacua_backend.candidate_domain import (  # noqa: E402
    ContractError,
    TICKET_CONTRACT,
    apply_transition,
)


POSITIVE = REPOSITORY_ROOT / "contracts" / "ticket-candidate" / "fixtures" / "positive"
FIXTURE_NAMES = (
    "version-1-draft.json",
    "version-2-needs-clarification.json",
    "version-3-ready.json",
    "version-4-approved.json",
)
REVIEWER = "reviewer_owner"


def chain(length: int) -> list[dict]:
    return [
        TICKET_CONTRACT.load_json(POSITIVE / name)
        for name in FIXTURE_NAMES[:length]
    ]


def transition_body(parent: dict, action: str, **values: object) -> dict:
    body = {
        "action": action,
        "actor_id": REVIEWER,
        "expected_candidate_id": parent["candidate_id"],
        "expected_candidate_version": parent["candidate_version"],
        "expected_candidate_digest": parent["candidate_digest"],
        "expected_candidate_content_digest": parent["candidate_content_digest"],
        "expected_evidence_manifest_digest": parent["evidence_manifest"]["manifest_digest"],
        "reason": f"reviewer_{action}",
    }
    if action == "resolve_clarification":
        body.update(
            {
                "clarification_id": "clarification_copy_source",
                "choice_id": "choice_use_approved",
                "resolution_note": None,
            }
        )
    elif action == "approve":
        body["approval_id"] = "approval_candidate_transition"
    body.update(values)
    return body


def at(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class CandidateDomainTests(unittest.TestCase):
    def assert_error(self, code: str, callback) -> ContractError:
        with self.assertRaises(ContractError) as caught:
            callback()
        self.assertEqual(code, caught.exception.code)
        return caught.exception

    def test_resolve_clarification_changes_only_declared_resolution(self) -> None:
        stored = chain(2)
        before = TICKET_CONTRACT.canonical_json(stored)
        parent = stored[-1]
        expected_content = copy.deepcopy(parent["content"])
        expected_clarification = expected_content["clarifications"][0]
        expected_clarification.update(
            {
                "status": "resolved",
                "selected_choice_id": "choice_use_approved",
                "resolution_note": None,
            }
        )

        result = apply_transition(
            stored,
            REVIEWER,
            transition_body(parent, "resolve_clarification"),
            at("2026-07-21T10:03:00Z"),
        )

        self.assertEqual(before, TICKET_CONTRACT.canonical_json(stored))
        self.assertEqual(expected_content, result["content"])
        self.assertEqual("ready_for_review", result["state"])
        self.assertEqual("clarification_answered", result["lineage"]["operation"])
        self.assertEqual(parent["candidate_digest"], result["previous_candidate_digest"])
        self.assertEqual(
            {
                "candidate_id": parent["candidate_id"],
                "candidate_version": parent["candidate_version"],
                "candidate_digest": parent["candidate_digest"],
            },
            result["lineage"]["parents"][0],
        )
        self.assertEqual(parent["evidence_manifest"], result["evidence_manifest"])
        for field in (
            "organization_id",
            "project_id",
            "build_id",
            "build_identity_digest",
            "session_id",
            "candidate_id",
            "candidate_created_at",
        ):
            self.assertEqual(parent[field], result[field])
        selected = result["content"]["clarifications"][0]
        selected_choice = next(
            choice
            for choice in selected["choices"]
            if choice["choice_id"] == selected["selected_choice_id"]
        )
        self.assertEqual(
            "The implementation ticket requests the Save profile label.",
            selected_choice["consequence"],
        )
        self.assertEqual(
            {
                "status": "reviewed",
                "reviewer_action_required": True,
                "last_human_actor_id": REVIEWER,
                "last_reviewed_at": "2026-07-21T10:03:00Z",
                "notes": parent["review"]["notes"],
            },
            result["review"],
        )
        self.assertIsNone(result["approval"])
        self.assertIsNone(result["rejection"])
        TICKET_CONTRACT.validate_chain([*stored, result])

    def test_resolution_remains_needs_clarification_while_blocker_remains(self) -> None:
        stored = chain(2)
        parent = stored[-1]
        other = copy.deepcopy(parent["content"]["clarifications"][0])
        other["clarification_id"] = "clarification_second_blocker"
        other["question"] = "Which secondary label should be used?"
        parent["content"]["clarifications"].append(other)
        stored[-1] = TICKET_CONTRACT.seal(parent)
        TICKET_CONTRACT.validate_chain(stored)

        result = apply_transition(
            stored,
            REVIEWER,
            transition_body(stored[-1], "resolve_clarification"),
            at("2026-07-21T10:03:00Z"),
        )

        self.assertEqual("needs_clarification", result["state"])
        self.assertEqual("in_review", result["review"]["status"])
        self.assertTrue(result["review"]["reviewer_action_required"])
        unresolved = [
            item
            for item in result["content"]["clarifications"]
            if item["impact"] == "blocking" and item["status"] == "unresolved"
        ]
        self.assertEqual(["clarification_second_blocker"], [item["clarification_id"] for item in unresolved])

    def test_required_resolution_note_and_declared_choice_are_enforced(self) -> None:
        stored = chain(2)
        parent = stored[-1]
        parent["content"]["clarifications"][0]["choices"][1]["requires_note"] = True
        stored[-1] = TICKET_CONTRACT.seal(parent)
        parent = stored[-1]
        TICKET_CONTRACT.validate_chain(stored)

        missing_field = transition_body(parent, "resolve_clarification")
        del missing_field["resolution_note"]
        self.assert_error(
            "TRANSITION_BODY_FIELDS",
            lambda: apply_transition(stored, REVIEWER, missing_field, at("2026-07-21T10:03:00Z")),
        )

        missing_note = transition_body(parent, "resolve_clarification")
        self.assert_error(
            "CLARIFICATION_NOTE_REQUIRED",
            lambda: apply_transition(stored, REVIEWER, missing_note, at("2026-07-21T10:03:00Z")),
        )

        unknown_choice = transition_body(
            parent,
            "resolve_clarification",
            choice_id="choice_not_declared",
            resolution_note="Use the approved product copy.",
        )
        self.assert_error(
            "UNDECLARED_CLARIFICATION_CHOICE",
            lambda: apply_transition(stored, REVIEWER, unknown_choice, at("2026-07-21T10:03:00Z")),
        )

        note = "Use the approved product copy."
        result = apply_transition(
            stored,
            REVIEWER,
            transition_body(parent, "resolve_clarification", resolution_note=note),
            at("2026-07-21T10:03:00Z"),
        )
        self.assertEqual(note, result["content"]["clarifications"][0]["resolution_note"])

    def test_all_optimistic_concurrency_bindings_are_exact(self) -> None:
        stored = chain(2)
        parent = stored[-1]
        cases = (
            (
                "expected_candidate_id",
                "candidate_other",
                "EXPECTED_CANDIDATE_ID_MISMATCH",
            ),
            (
                "expected_candidate_version",
                parent["candidate_version"] - 1,
                "EXPECTED_CANDIDATE_VERSION_MISMATCH",
            ),
            (
                "expected_candidate_digest",
                "sha256:" + "0" * 64,
                "EXPECTED_CANDIDATE_DIGEST_MISMATCH",
            ),
            (
                "expected_candidate_content_digest",
                "sha256:" + "1" * 64,
                "EXPECTED_CONTENT_DIGEST_MISMATCH",
            ),
            (
                "expected_evidence_manifest_digest",
                "sha256:" + "2" * 64,
                "EXPECTED_EVIDENCE_DIGEST_MISMATCH",
            ),
        )
        for field, value, code in cases:
            with self.subTest(field=field):
                body = transition_body(parent, "resolve_clarification")
                body[field] = value
                self.assert_error(
                    code,
                    lambda body=body: apply_transition(
                        stored,
                        REVIEWER,
                        body,
                        at("2026-07-21T10:03:00Z"),
                    ),
                )

    def test_authenticated_identity_is_authoritative_and_body_is_closed(self) -> None:
        stored = chain(3)
        parent = stored[-1]
        mismatched = transition_body(parent, "approve", actor_id="reviewer_other")
        self.assert_error(
            "REVIEWER_MISMATCH",
            lambda: apply_transition(stored, REVIEWER, mismatched, at("2026-07-21T10:04:00Z")),
        )

        expanded = transition_body(parent, "approve")
        expanded["content"] = {"title": "silently changed"}
        self.assert_error(
            "TRANSITION_BODY_FIELDS",
            lambda: apply_transition(stored, REVIEWER, expanded, at("2026-07-21T10:04:00Z")),
        )

        result = apply_transition(
            stored,
            REVIEWER,
            transition_body(parent, "approve"),
            at("2026-07-21T10:04:00Z"),
        )
        self.assertEqual(REVIEWER, result["transition"]["actor"]["actor_id"])
        self.assertEqual(REVIEWER, result["approval"]["actor_id"])

    def test_each_action_rejects_illegal_parent_states(self) -> None:
        draft = chain(1)
        needs = chain(2)
        ready = chain(3)
        cases = (
            (needs, transition_body(needs[-1], "approve")),
            (draft, transition_body(draft[-1], "reject")),
            (ready, transition_body(ready[-1], "resolve_clarification")),
            (ready, transition_body(ready[-1], "mark_ready")),
        )
        for stored, body in cases:
            with self.subTest(action=body["action"], state=stored[-1]["state"]):
                self.assert_error(
                    "ILLEGAL_TRANSITION_ACTION",
                    lambda stored=stored, body=body: apply_transition(
                        stored,
                        REVIEWER,
                        body,
                        at("2026-07-21T10:05:00Z"),
                    ),
                )

        self.assert_error(
            "UNRESOLVED_BLOCKING_CLARIFICATION",
            lambda: apply_transition(
                draft,
                REVIEWER,
                transition_body(draft[-1], "mark_ready"),
                at("2026-07-21T10:01:00Z"),
            ),
        )

    def test_mark_ready_preserves_content_and_sets_review_snapshot(self) -> None:
        stored = chain(1)
        draft = stored[-1]
        clarification = draft["content"]["clarifications"][0]
        clarification.update(
            {
                "status": "resolved",
                "selected_choice_id": "choice_use_approved",
                "resolution_note": None,
            }
        )
        stored[-1] = TICKET_CONTRACT.seal(draft)
        TICKET_CONTRACT.validate_chain(stored)
        parent = stored[-1]

        result = apply_transition(
            stored,
            REVIEWER,
            transition_body(parent, "mark_ready"),
            at("2026-07-21T10:01:00Z"),
        )

        self.assertEqual("ready_for_review", result["state"])
        self.assertEqual("reviewed", result["lineage"]["operation"])
        self.assertEqual(parent["content"], result["content"])
        self.assertEqual(parent["candidate_content_digest"], result["candidate_content_digest"])
        self.assertEqual("reviewed", result["review"]["status"])
        self.assertTrue(result["review"]["reviewer_action_required"])

    def test_approval_binds_exact_parent_content_manifest_and_referenced_evidence(self) -> None:
        stored = chain(3)
        parent = stored[-1]
        result = apply_transition(
            stored,
            REVIEWER,
            transition_body(parent, "approve"),
            at("2026-07-21T10:04:00Z"),
        )

        approval = result["approval"]
        self.assertEqual("approved", result["state"])
        self.assertEqual("approved", result["lineage"]["operation"])
        self.assertEqual(parent["content"], result["content"])
        self.assertEqual(parent["evidence_manifest"], result["evidence_manifest"])
        self.assertEqual(parent["candidate_version"], approval["reviewed_candidate_version"])
        self.assertEqual(parent["candidate_digest"], approval["reviewed_candidate_digest"])
        self.assertEqual(result["candidate_version"], approval["approved_candidate_version"])
        self.assertEqual(result["candidate_content_digest"], approval["candidate_content_digest"])
        self.assertEqual(
            parent["evidence_manifest"]["manifest_digest"],
            approval["evidence_manifest_digest"],
        )
        self.assertEqual(
            sorted(TICKET_CONTRACT.content_evidence_refs(parent["content"])),
            approval["authorized_evidence_ids"],
        )
        self.assertTrue(approval["immutable"])
        self.assertFalse(result["review"]["reviewer_action_required"])
        self.assertIsNone(result["rejection"])

    def test_rejects_needs_clarification_and_ready_with_exact_binding(self) -> None:
        for length, timestamp in ((2, "2026-07-21T10:03:00Z"), (3, "2026-07-21T10:04:00Z")):
            with self.subTest(length=length):
                stored = chain(length)
                parent = stored[-1]
                body = transition_body(
                    parent,
                    "reject",
                    reason="The candidate should not be handed to an agent.",
                )
                result = apply_transition(stored, REVIEWER, body, at(timestamp))
                rejection = result["rejection"]
                self.assertEqual("rejected", result["state"])
                self.assertEqual(parent["content"], result["content"])
                self.assertEqual(parent["candidate_digest"], rejection["reviewed_candidate_digest"])
                self.assertEqual(parent["candidate_version"], rejection["reviewed_candidate_version"])
                self.assertEqual(result["candidate_version"], rejection["rejected_candidate_version"])
                self.assertEqual(result["candidate_content_digest"], rejection["candidate_content_digest"])
                self.assertEqual(body["reason"], rejection["reason"])
                self.assertEqual(REVIEWER, rejection["actor_id"])
                self.assertTrue(rejection["immutable"])
                self.assertIsNone(result["approval"])

    def test_server_time_bump_is_strict_and_deterministic(self) -> None:
        stored = chain(3)
        parent = stored[-1]
        body = transition_body(parent, "approve")
        supplied = datetime(2026, 7, 21, 10, 3, 0, 999999, tzinfo=timezone.utc)

        first = apply_transition(stored, REVIEWER, body, supplied)
        second = apply_transition(stored, REVIEWER, copy.deepcopy(body), supplied)

        self.assertEqual("2026-07-21T10:03:01Z", first["version_created_at"])
        self.assertEqual(first["version_created_at"], first["transition"]["occurred_at"])
        self.assertEqual(first["version_created_at"], first["review"]["last_reviewed_at"])
        self.assertEqual(first["version_created_at"], first["approval"]["approved_at"])
        self.assertEqual(TICKET_CONTRACT.canonical_json(first), TICKET_CONTRACT.canonical_json(second))
        self.assertEqual(first["candidate_digest"], second["candidate_digest"])

    def test_invalid_stored_chain_and_naive_server_time_fail_closed(self) -> None:
        stored = chain(2)
        body = transition_body(stored[-1], "resolve_clarification")
        corrupted = copy.deepcopy(stored)
        corrupted[-1]["content"]["title"] = "mutated without resealing"
        self.assert_error(
            "CONTENT_DIGEST_MISMATCH",
            lambda: apply_transition(corrupted, REVIEWER, body, at("2026-07-21T10:03:00Z")),
        )
        self.assert_error(
            "SERVER_TIME_INVALID",
            lambda: apply_transition(stored, REVIEWER, body, datetime(2026, 7, 21, 10, 3, 0)),
        )


if __name__ == "__main__":
    unittest.main()
