# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE = REPOSITORY_ROOT / "services" / "backend" / "src"
sys.path.insert(0, str(SOURCE))

from tacua_backend.candidate_domain import TICKET_CONTRACT  # noqa: E402
from tacua_backend.candidate_store import (  # noqa: E402
    CandidateStore,
    CandidateStoreError,
)
from tacua_backend.evidence_domain import EvidenceDomainError  # noqa: E402


FIXTURE = (
    REPOSITORY_ROOT
    / "contracts"
    / "ticket-candidate"
    / "fixtures"
    / "positive"
    / "version-1-draft.json"
)
REVIEWER = "reviewer_owner"


class FakeClock:
    def __init__(self, value: str):
        self.value = parse_time(value)
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            return self.value

    def set(self, value: str) -> None:
        with self._lock:
            self.value = parse_time(value)


def parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def body(parent: dict, action: str, **changes: object) -> dict:
    result = {
        "expected_candidate_digest": parent["candidate_digest"],
        "candidate_version": parent["candidate_version"],
        "candidate_content_digest": parent["candidate_content_digest"],
        "evidence_manifest_digest": parent["evidence_manifest"]["manifest_digest"],
        "action": action,
        "actor_id": REVIEWER,
        "reason": f"reviewer_{action}",
    }
    if action == "resolve_clarification":
        result.update(
            {
                "clarification_id": "clarification_copy_source",
                "selected_choice_id": "choice_use_approved",
            }
        )
    result.update(changes)
    return result


class CandidateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "candidate.sqlite3"
        self.clock = FakeClock("2026-07-21T10:01:00Z")

        def connect() -> sqlite3.Connection:
            return sqlite3.connect(self.database, timeout=10)

        self.connect = connect
        self.store = CandidateStore(
            connect,
            organization_id="org_synthetic",
            project_id="project_sample_mobile",
            reviewer_id=REVIEWER,
            clock=self.clock,
        )
        self.store.initialize_schema()
        self.generated = TICKET_CONTRACT.load_json(FIXTURE)

    def assert_store_error(self, status: int, code: str, callback) -> CandidateStoreError:
        with self.assertRaises(CandidateStoreError) as caught:
            callback()
        self.assertEqual(status, caught.exception.status)
        self.assertEqual(code, caught.exception.code)
        return caught.exception

    def insert(self) -> dict:
        return self.store.insert_generated(self.generated)

    def store_with_hooks(self, **hooks: object) -> CandidateStore:
        return CandidateStore(
            self.connect,
            organization_id="org_synthetic",
            project_id="project_sample_mobile",
            reviewer_id=REVIEWER,
            clock=self.clock,
            **hooks,
        )

    def resolve(self, parent: dict | None = None, key: str = "resolve:001"):
        parent = parent or self.store.get(self.generated["candidate_id"])
        return self.store.transition(
            parent["candidate_id"],
            if_match=parent["candidate_digest"],
            idempotency_key=key,
            body=body(parent, "resolve_clarification"),
        )

    def test_insert_list_and_exact_version_lookup(self) -> None:
        inserted = self.insert()
        self.assertEqual(self.generated, inserted)
        self.assertEqual([self.generated], self.store.list_current(self.generated["session_id"]))
        self.assertEqual(self.generated, self.store.get(self.generated["candidate_id"], 1))
        self.assertEqual(self.generated, self.store.insert_generated(copy.deepcopy(self.generated)))

        conflict = copy.deepcopy(self.generated)
        conflict["content"]["title"] = "A different ticket"
        conflict = TICKET_CONTRACT.seal(conflict)
        self.assert_store_error(
            409,
            "CANDIDATE_ALREADY_EXISTS",
            lambda: self.store.insert_generated(conflict),
        )

    def test_generated_insert_guard_runs_atomically_before_candidate_writes(self) -> None:
        with closing(self.connect()) as connection, connection:
            connection.execute(
                "CREATE TABLE generated_guard_probe (candidate_digest TEXT NOT NULL)"
            )
        observed: list[dict] = []

        def guard(connection: sqlite3.Connection, document: dict) -> None:
            self.assertTrue(connection.in_transaction)
            self.assertEqual(
                0,
                connection.execute("SELECT COUNT(*) FROM candidate_versions").fetchone()[0],
            )
            self.assertEqual(
                0,
                connection.execute("SELECT COUNT(*) FROM candidate_heads").fetchone()[0],
            )
            observed.append(copy.deepcopy(document))
            connection.execute(
                "INSERT INTO generated_guard_probe (candidate_digest) VALUES (?)",
                (document["candidate_digest"],),
            )
            document["state"] = "mutated_guard_copy"

        guarded = self.store_with_hooks(generated_insert_guard=guard)
        self.assertEqual(self.generated, guarded.insert_generated(self.generated))
        self.assertEqual([self.generated], observed)
        self.assertEqual(self.generated, guarded.get(self.generated["candidate_id"]))
        with closing(self.connect()) as connection, connection:
            self.assertEqual(
                (self.generated["candidate_digest"],),
                tuple(connection.execute("SELECT candidate_digest FROM generated_guard_probe").fetchone()),
            )

        self.assertEqual(self.generated, guarded.insert_generated(copy.deepcopy(self.generated)))
        self.assertEqual([self.generated], observed)

    def test_generated_insert_guard_failure_rolls_back_every_write(self) -> None:
        with closing(self.connect()) as connection, connection:
            connection.execute(
                "CREATE TABLE generated_guard_probe (candidate_digest TEXT NOT NULL)"
            )

        def guard(connection: sqlite3.Connection, document: dict) -> None:
            self.assertTrue(connection.in_transaction)
            connection.execute(
                "INSERT INTO generated_guard_probe (candidate_digest) VALUES (?)",
                (document["candidate_digest"],),
            )
            raise CandidateStoreError(
                409,
                "SESSION_PUBLICATION_CLOSED",
                "session no longer accepts generated candidates",
            )

        guarded = self.store_with_hooks(generated_insert_guard=guard)
        self.assert_store_error(
            409,
            "SESSION_PUBLICATION_CLOSED",
            lambda: guarded.insert_generated(self.generated),
        )
        with closing(self.connect()) as connection, connection:
            for table in (
                "candidate_versions",
                "candidate_heads",
                "generated_guard_probe",
            ):
                self.assertEqual(
                    0,
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                )

    def test_draft_resolution_and_approval_are_durable_immutable_versions(self) -> None:
        self.insert()
        resolved_response = self.resolve()
        resolved = json.loads(resolved_response.body)
        self.assertEqual("ready_for_review", resolved["state"])
        self.assertEqual(2, resolved["candidate_version"])
        self.assertEqual(resolved["candidate_digest"], resolved_response.candidate_digest)

        self.clock.set("2026-07-21T10:02:00Z")
        approved_response = self.store.transition(
            resolved["candidate_id"],
            if_match=resolved["candidate_digest"],
            idempotency_key="approve:001",
            body=body(resolved, "approve"),
        )
        approved = json.loads(approved_response.body)
        self.assertEqual("approved", approved["state"])
        self.assertEqual(3, approved["candidate_version"])
        self.assertEqual(resolved["candidate_digest"], approved["approval"]["reviewed_candidate_digest"])
        self.assertEqual(self.generated, self.store.get(self.generated["candidate_id"], 1))
        TICKET_CONTRACT.validate_chain(
            [self.store.get(self.generated["candidate_id"], version) for version in (1, 2, 3)]
        )

    def test_approval_guard_runs_on_exact_parent_and_rolls_back_its_writes(self) -> None:
        self.insert()
        resolved = json.loads(self.resolve().body)
        with closing(self.connect()) as connection, connection:
            connection.execute(
                "CREATE TABLE approval_guard_probe (candidate_digest TEXT NOT NULL)"
            )
        observed: list[dict] = []

        def guard(connection: sqlite3.Connection, parent: dict) -> None:
            self.assertTrue(connection.in_transaction)
            observed.append(copy.deepcopy(parent))
            connection.execute(
                "INSERT INTO approval_guard_probe (candidate_digest) VALUES (?)",
                (parent["candidate_digest"],),
            )
            parent["state"] = "mutated_guard_copy"
            raise EvidenceDomainError(
                "PREVIEW_UNAVAILABLE",
                "$.evidence_ids[0]",
                "approval keyframe is unavailable",
            )

        guarded = self.store_with_hooks(approval_guard=guard)
        error = self.assert_store_error(
            409,
            "PREVIEW_UNAVAILABLE",
            lambda: guarded.transition(
                resolved["candidate_id"],
                if_match=resolved["candidate_digest"],
                idempotency_key="approve:guarded",
                body=body(resolved, "approve"),
            ),
        )
        self.assertEqual("approval keyframe is unavailable", error.message)
        self.assertEqual([resolved], observed)
        self.assertEqual(resolved, guarded.get(resolved["candidate_id"]))
        with closing(self.connect()) as connection, connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM approval_guard_probe"
                ).fetchone()[0],
            )
            self.assertEqual(
                2,
                connection.execute("SELECT COUNT(*) FROM candidate_versions").fetchone()[0],
            )
            self.assertEqual(
                1,
                connection.execute("SELECT COUNT(*) FROM candidate_operations").fetchone()[0],
            )

        mismatched = body(
            resolved,
            "approve",
            candidate_content_digest="sha256:" + "0" * 64,
        )
        self.assert_store_error(
            412,
            "CANDIDATE_PRECONDITION_FAILED",
            lambda: guarded.transition(
                resolved["candidate_id"],
                if_match=resolved["candidate_digest"],
                idempotency_key="approve:mismatched-before-guard",
                body=mismatched,
            ),
        )
        self.assertEqual([resolved], observed)

        type_confused = body(resolved, "approve", candidate_version=True)
        self.assert_store_error(
            412,
            "CANDIDATE_PRECONDITION_FAILED",
            lambda: guarded.transition(
                resolved["candidate_id"],
                if_match=resolved["candidate_digest"],
                idempotency_key="approve:type-confused-before-guard",
                body=type_confused,
            ),
        )
        self.assertEqual([resolved], observed)

    def test_approval_guard_does_not_run_for_other_actions(self) -> None:
        calls: list[str] = []

        def guard(connection: sqlite3.Connection, parent: dict) -> None:
            calls.append(parent["candidate_digest"])

        guarded = self.store_with_hooks(approval_guard=guard)
        guarded.insert_generated(self.generated)
        parent = guarded.get(self.generated["candidate_id"])
        guarded.transition(
            parent["candidate_id"],
            if_match=parent["candidate_digest"],
            idempotency_key="resolve:no-approval-guard",
            body=body(parent, "resolve_clarification"),
        )
        self.assertEqual([], calls)

    def test_version_append_guard_sees_exact_sealed_pair_before_insert(self) -> None:
        parent = self.insert()
        with closing(self.connect()) as connection, connection:
            connection.execute(
                """CREATE TABLE version_guard_probe (
                       parent_digest TEXT NOT NULL,
                       child_digest TEXT NOT NULL
                   )"""
            )
        observed: list[tuple[dict, dict]] = []

        def append_guard(
            connection: sqlite3.Connection,
            exact_parent: dict,
            exact_child: dict,
        ) -> None:
            self.assertTrue(connection.in_transaction)
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM candidate_versions WHERE candidate_digest = ?",
                    (exact_child["candidate_digest"],),
                ).fetchone()[0],
            )
            head = connection.execute(
                "SELECT candidate_digest FROM candidate_heads WHERE candidate_id = ?",
                (exact_parent["candidate_id"],),
            ).fetchone()
            self.assertEqual(exact_parent["candidate_digest"], head[0])
            observed.append((copy.deepcopy(exact_parent), copy.deepcopy(exact_child)))
            connection.execute(
                """INSERT INTO version_guard_probe (parent_digest, child_digest)
                   VALUES (?, ?)""",
                (exact_parent["candidate_digest"], exact_child["candidate_digest"]),
            )
            exact_parent["state"] = "mutated_parent_copy"
            exact_child["state"] = "mutated_child_copy"

        guarded = self.store_with_hooks(version_append_guard=append_guard)
        response = guarded.transition(
            parent["candidate_id"],
            if_match=parent["candidate_digest"],
            idempotency_key="resolve:version-hook",
            body=body(parent, "resolve_clarification"),
        )
        child = json.loads(response.body)
        self.assertEqual([(parent, child)], observed)
        self.assertEqual(child, guarded.get(parent["candidate_id"]))
        with closing(self.connect()) as connection, connection:
            self.assertEqual(
                (parent["candidate_digest"], child["candidate_digest"]),
                tuple(connection.execute(
                    "SELECT parent_digest, child_digest FROM version_guard_probe"
                ).fetchone()),
            )

    def test_version_append_guard_failure_rolls_back_every_transition_write(self) -> None:
        parent = self.insert()
        with closing(self.connect()) as connection, connection:
            connection.execute(
                "CREATE TABLE version_guard_probe (candidate_digest TEXT NOT NULL)"
            )

        def append_guard(
            connection: sqlite3.Connection,
            exact_parent: dict,
            exact_child: dict,
        ) -> None:
            self.assertTrue(connection.in_transaction)
            connection.execute(
                "INSERT INTO version_guard_probe (candidate_digest) VALUES (?)",
                (exact_child["candidate_digest"],),
            )
            raise CandidateStoreError(
                409,
                "EVIDENCE_BINDING_APPEND_FAILED",
                "new candidate evidence binding could not be appended",
            )

        guarded = self.store_with_hooks(version_append_guard=append_guard)
        self.assert_store_error(
            409,
            "EVIDENCE_BINDING_APPEND_FAILED",
            lambda: guarded.transition(
                parent["candidate_id"],
                if_match=parent["candidate_digest"],
                idempotency_key="resolve:version-hook-failure",
                body=body(parent, "resolve_clarification"),
            ),
        )
        self.assertEqual(parent, guarded.get(parent["candidate_id"]))
        with closing(self.connect()) as connection, connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM version_guard_probe"
                ).fetchone()[0],
            )
            self.assertEqual(
                1,
                connection.execute("SELECT COUNT(*) FROM candidate_versions").fetchone()[0],
            )
            self.assertEqual(
                0,
                connection.execute("SELECT COUNT(*) FROM candidate_operations").fetchone()[0],
            )

    def test_exact_idempotent_retry_survives_head_movement(self) -> None:
        self.insert()
        parent = self.store.get(self.generated["candidate_id"])
        first = self.resolve(parent, "resolve:lost-response")
        second = self.resolve(parent, "resolve:lost-response")

        self.assertEqual(first, second)
        self.assertEqual(2, self.store.get(parent["candidate_id"])["candidate_version"])
        with closing(self.connect()) as connection, connection:
            versions = connection.execute("SELECT COUNT(*) FROM candidate_versions").fetchone()[0]
            operations = connection.execute("SELECT COUNT(*) FROM candidate_operations").fetchone()[0]
        self.assertEqual(2, versions)
        self.assertEqual(1, operations)

    def test_idempotency_conflict_and_stale_precondition_fail_without_writes(self) -> None:
        self.insert()
        parent = self.store.get(self.generated["candidate_id"])
        self.resolve(parent, "resolve:shared")
        changed = body(parent, "resolve_clarification", reason="different reason")
        self.assert_store_error(
            409,
            "IDEMPOTENCY_CONFLICT",
            lambda: self.store.transition(
                parent["candidate_id"],
                if_match=parent["candidate_digest"],
                idempotency_key="resolve:shared",
                body=changed,
            ),
        )
        self.assert_store_error(
            412,
            "CANDIDATE_PRECONDITION_FAILED",
            lambda: self.store.transition(
                parent["candidate_id"],
                if_match=parent["candidate_digest"],
                idempotency_key="resolve:stale",
                body=body(parent, "resolve_clarification"),
            ),
        )
        with closing(self.connect()) as connection, connection:
            self.assertEqual(2, connection.execute("SELECT COUNT(*) FROM candidate_versions").fetchone()[0])
            self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM candidate_operations").fetchone()[0])

    def test_actor_body_and_etag_bindings_fail_closed(self) -> None:
        self.insert()
        parent = self.store.get(self.generated["candidate_id"])
        wrong_actor = body(parent, "resolve_clarification", actor_id="reviewer_other")
        self.assert_store_error(
            403,
            "REVIEWER_MISMATCH",
            lambda: self.store.transition(
                parent["candidate_id"],
                if_match=parent["candidate_digest"],
                idempotency_key="resolve:wrong-actor",
                body=wrong_actor,
            ),
        )
        mismatched = body(
            parent,
            "resolve_clarification",
            expected_candidate_digest="sha256:" + "0" * 64,
        )
        self.assert_store_error(
            412,
            "CANDIDATE_PRECONDITION_FAILED",
            lambda: self.store.transition(
                parent["candidate_id"],
                if_match=parent["candidate_digest"],
                idempotency_key="resolve:mismatch",
                body=mismatched,
            ),
        )

    def test_two_distinct_requests_cannot_advance_the_same_head(self) -> None:
        self.insert()
        parent = self.store.get(self.generated["candidate_id"])
        barrier = threading.Barrier(3)
        results: list[tuple[str, int]] = []
        lock = threading.Lock()

        def run(key: str) -> None:
            barrier.wait()
            try:
                self.resolve(parent, key)
                outcome = ("ok", 200)
            except CandidateStoreError as exc:
                outcome = (exc.code, exc.status)
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=run, args=(f"resolve:race:{index}",)) for index in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(
            sorted([("ok", 200), ("CANDIDATE_PRECONDITION_FAILED", 412)]),
            sorted(results),
        )

    def test_session_deletion_removes_versions_heads_and_retry_responses(self) -> None:
        self.insert()
        self.resolve()
        counts = self.store.delete_session(self.generated["session_id"])
        self.assertEqual(
            {"candidate_heads": 1, "candidate_versions": 2, "candidate_operations": 1},
            counts,
        )
        self.assertEqual(
            {"candidate_heads": 0, "candidate_versions": 0, "candidate_operations": 0},
            self.store.delete_session(self.generated["session_id"]),
        )
        self.assert_store_error(
            404,
            "CANDIDATE_NOT_FOUND",
            lambda: self.store.get(self.generated["candidate_id"]),
        )

    def test_session_deletion_uses_bounded_scope_query_for_many_candidates(self) -> None:
        session_id = "session_bulk_delete"
        count = 1_100
        version_rows = []
        head_rows = []
        operation_rows = []
        for index in range(count):
            candidate_id = f"candidate_bulk_{index:04d}"
            candidate_digest = f"sha256:{index + 1:064x}"
            version_rows.append(
                (
                    candidate_id,
                    1,
                    "org_synthetic",
                    "project_sample_mobile",
                    session_id,
                    "draft",
                    candidate_digest,
                    "sha256:" + "1" * 64,
                    "sha256:" + "2" * 64,
                    "{}",
                    "2026-07-21T10:00:00Z",
                )
            )
            head_rows.append(
                (
                    candidate_id,
                    1,
                    candidate_digest,
                    "org_synthetic",
                    "project_sample_mobile",
                    session_id,
                    "draft",
                )
            )
            operation_rows.append(
                (
                    REVIEWER,
                    f"bulk:{index}",
                    candidate_id,
                    "sha256:" + "3" * 64,
                    200,
                    b"{}",
                    "sha256:" + "4" * 64,
                    "2026-07-21T10:00:00Z",
                )
            )
        with closing(self.connect()) as connection, connection:
            connection.executemany(
                """INSERT INTO candidate_versions (
                       candidate_id, candidate_version, organization_id,
                       project_id, session_id, state, candidate_digest,
                       candidate_content_digest, evidence_manifest_digest,
                       canonical_json, version_created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                version_rows,
            )
            connection.executemany(
                """INSERT INTO candidate_heads (
                       candidate_id, candidate_version, candidate_digest,
                       organization_id, project_id, session_id, state
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                head_rows,
            )
            connection.executemany(
                """INSERT INTO candidate_operations (
                       reviewer_id, idempotency_key, candidate_id,
                       request_digest, response_status, response_body,
                       response_digest, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                operation_rows,
            )
        self.assertEqual(
            {
                "candidate_heads": count,
                "candidate_versions": count,
                "candidate_operations": count,
            },
            self.store.delete_session(session_id),
        )

    def test_stored_candidate_tampering_is_detected(self) -> None:
        self.insert()
        with closing(self.connect()) as connection, connection:
            raw = connection.execute("SELECT canonical_json FROM candidate_versions").fetchone()[0]
            document = json.loads(raw)
            document["content"]["title"] = "Tampered"
            connection.execute(
                "UPDATE candidate_versions SET canonical_json = ?",
                (json.dumps(document, sort_keys=True, separators=(",", ":")),),
            )
        self.assert_store_error(
            500,
            "CANDIDATE_STORAGE_CORRUPT",
            lambda: self.store.get(self.generated["candidate_id"]),
        )


if __name__ == "__main__":
    unittest.main()
