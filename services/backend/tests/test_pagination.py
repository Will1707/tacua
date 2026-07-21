# SPDX-License-Identifier: Apache-2.0
"""Bounded keyset pagination regressions for reviewer/admin lists."""

from __future__ import annotations

import base64
import copy
from email.message import Message
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_backend import BackendHarness

from tacua_backend.candidate_domain import TICKET_CONTRACT
from tacua_backend.contracts import canonical_json
from tacua_backend.http_api import PilotRequestHandler
from tacua_backend.service import ApiError


class PaginationDataMixin:
    backend: object

    def _seed_sessions(self, count: int = 52) -> list[str]:
        assert isinstance(self, BackendHarness)
        _request, receipt, _body, _grant = self.start_session()
        with self.backend._connect() as connection:
            source = connection.execute(
                """SELECT state,scope_digest,scope_json,build_identity_digest,
                          build_identity_json,created_at,completed_at,
                          raw_media_expires_at,derived_data_expires_at,completion_id
                     FROM sessions WHERE session_id = ?""",
                (receipt["session_id"],),
            ).fetchone()
            assert source is not None
            connection.execute("DELETE FROM sessions")
            session_ids = [f"session_page_{index:03d}" for index in range(count)]
            for session_id in session_ids:
                connection.execute(
                    """INSERT INTO sessions
                       (session_id,state,scope_digest,scope_json,build_identity_digest,
                        build_identity_json,created_at,completed_at,raw_media_expires_at,
                        derived_data_expires_at,completion_id)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        session_id,
                        source["state"],
                        source["scope_digest"],
                        source["scope_json"],
                        source["build_identity_digest"],
                        source["build_identity_json"],
                        source["created_at"],
                        source["completed_at"],
                        source["raw_media_expires_at"],
                        source["derived_data_expires_at"],
                        source["completion_id"],
                    ),
                )
        return session_ids

    def _seed_candidates(
        self,
        session_id: str,
        count: int = 52,
    ) -> dict[str, dict]:
        assert isinstance(self, BackendHarness)
        base, _manifest, _previews = self.candidate_bundle(session_id)
        candidates: dict[str, dict] = {}
        with self.backend._connect() as connection:
            for index in range(count):
                candidate = copy.deepcopy(base)
                candidate_id = f"candidate_page_{index:03d}"
                candidate["candidate_id"] = candidate_id
                candidate["content"]["title"] = f"Paginated candidate {index:03d}"
                candidate["content"]["summary"]["text"] = f"Summary {index:03d}"
                candidate = TICKET_CONTRACT.seal(candidate)
                TICKET_CONTRACT.validate_chain([candidate])
                connection.execute(
                    """INSERT INTO candidate_versions
                       (candidate_id,candidate_version,organization_id,project_id,
                        session_id,state,candidate_digest,candidate_content_digest,
                        evidence_manifest_digest,canonical_json,version_created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        candidate_id,
                        candidate["candidate_version"],
                        candidate["organization_id"],
                        candidate["project_id"],
                        candidate["session_id"],
                        candidate["state"],
                        candidate["candidate_digest"],
                        candidate["candidate_content_digest"],
                        candidate["evidence_manifest"]["manifest_digest"],
                        canonical_json(candidate),
                        candidate["version_created_at"],
                    ),
                )
                connection.execute(
                    """INSERT INTO candidate_heads
                       (candidate_id,candidate_version,candidate_digest,organization_id,
                        project_id,session_id,state)
                       VALUES (?,?,?,?,?,?,?)""",
                    (
                        candidate_id,
                        candidate["candidate_version"],
                        candidate["candidate_digest"],
                        candidate["organization_id"],
                        candidate["project_id"],
                        candidate["session_id"],
                        candidate["state"],
                    ),
                )
                candidates[candidate_id] = candidate
        return candidates

    def _transition_candidate_head(self, parent: dict) -> dict:
        assert isinstance(self, BackendHarness)
        occurred_at = "2026-07-21T10:01:00Z"
        candidate = copy.deepcopy(parent)
        candidate.update(
            {
                "candidate_version": 2,
                "previous_candidate_digest": parent["candidate_digest"],
                "state": "needs_clarification",
                "version_created_at": occurred_at,
                "lineage": {
                    "operation": "reviewed",
                    "parents": [
                        {
                            "candidate_id": parent["candidate_id"],
                            "candidate_version": parent["candidate_version"],
                            "candidate_digest": parent["candidate_digest"],
                        }
                    ],
                },
                "transition": {
                    "from_state": "draft",
                    "to_state": "needs_clarification",
                    "actor": {
                        "actor_type": "human",
                        "actor_id": self.config.reviewer_id,
                    },
                    "occurred_at": occurred_at,
                    "reason": "reviewer_started_paginated_candidate_review",
                },
                "review": {
                    "status": "in_review",
                    "reviewer_action_required": True,
                    "last_human_actor_id": self.config.reviewer_id,
                    "last_reviewed_at": occurred_at,
                    "notes": [],
                },
            }
        )
        candidate = TICKET_CONTRACT.seal(candidate)
        TICKET_CONTRACT.validate_chain([parent, candidate])
        with self.backend._connect() as connection:
            connection.execute(
                """INSERT INTO candidate_versions
                   (candidate_id,candidate_version,organization_id,project_id,
                    session_id,state,candidate_digest,candidate_content_digest,
                    evidence_manifest_digest,canonical_json,version_created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    candidate["candidate_id"],
                    candidate["candidate_version"],
                    candidate["organization_id"],
                    candidate["project_id"],
                    candidate["session_id"],
                    candidate["state"],
                    candidate["candidate_digest"],
                    candidate["candidate_content_digest"],
                    candidate["evidence_manifest"]["manifest_digest"],
                    canonical_json(candidate),
                    candidate["version_created_at"],
                ),
            )
            connection.execute(
                """UPDATE candidate_heads
                      SET candidate_version = ?, candidate_digest = ?, state = ?
                    WHERE candidate_id = ?""",
                (
                    candidate["candidate_version"],
                    candidate["candidate_digest"],
                    candidate["state"],
                    candidate["candidate_id"],
                ),
            )
        return candidate


class PaginationServiceTests(PaginationDataMixin, BackendHarness):
    def test_session_summaries_reject_tampered_storage_projections(self) -> None:
        completed = self.full_completed_session()
        session_id = completed["launch_receipt"]["session_id"]
        baseline = self.backend.list_sessions()
        self.assertEqual(
            completed["completion_request"]["capture_manifest"]["manifest_digest"],
            baseline["sessions"][0]["manifest_digest"],
        )

        with self.backend._connect() as connection:
            session = connection.execute(
                """SELECT scope_digest,scope_json,build_identity_digest,
                          build_identity_json
                     FROM sessions WHERE session_id = ?""",
                (session_id,),
            ).fetchone()
            completion = connection.execute(
                """SELECT request_digest,request_json
                     FROM completions WHERE session_id = ?""",
                (session_id,),
            ).fetchone()
        assert session is not None
        assert completion is not None

        mutations = (
            (
                "scope document",
                "UPDATE sessions SET scope_json = ? WHERE session_id = ?",
                ("{}", session_id),
                "UPDATE sessions SET scope_json = ? WHERE session_id = ?",
                (session["scope_json"], session_id),
            ),
            (
                "scope digest projection",
                "UPDATE sessions SET scope_digest = ? WHERE session_id = ?",
                ("sha256:" + "f" * 64, session_id),
                "UPDATE sessions SET scope_digest = ? WHERE session_id = ?",
                (session["scope_digest"], session_id),
            ),
            (
                "build document",
                "UPDATE sessions SET build_identity_json = ? WHERE session_id = ?",
                ("{}", session_id),
                "UPDATE sessions SET build_identity_json = ? WHERE session_id = ?",
                (session["build_identity_json"], session_id),
            ),
            (
                "build digest projection",
                "UPDATE sessions SET build_identity_digest = ? WHERE session_id = ?",
                ("sha256:" + "f" * 64, session_id),
                "UPDATE sessions SET build_identity_digest = ? WHERE session_id = ?",
                (session["build_identity_digest"], session_id),
            ),
            (
                "completion document",
                "UPDATE completions SET request_json = ? WHERE session_id = ?",
                ("{}", session_id),
                "UPDATE completions SET request_json = ? WHERE session_id = ?",
                (completion["request_json"], session_id),
            ),
            (
                "completion digest projection",
                "UPDATE completions SET request_digest = ? WHERE session_id = ?",
                ("sha256:" + "f" * 64, session_id),
                "UPDATE completions SET request_digest = ? WHERE session_id = ?",
                (completion["request_digest"], session_id),
            ),
        )
        for label, mutate_sql, mutate_args, restore_sql, restore_args in mutations:
            with self.subTest(label=label):
                try:
                    with self.backend._connect() as connection:
                        connection.execute(mutate_sql, mutate_args)
                    with self.assertRaises(ApiError) as captured:
                        self.backend.list_sessions()
                    self.assertEqual(500, captured.exception.status)
                    self.assertEqual("SESSION_STORAGE_CORRUPT", captured.exception.code)
                finally:
                    with self.backend._connect() as connection:
                        connection.execute(restore_sql, restore_args)

        with self.backend._connect() as connection:
            connection.execute(
                "DELETE FROM completions WHERE session_id = ?",
                (session_id,),
            )
        with self.assertRaises(ApiError) as captured:
            self.backend.list_sessions()
        self.assertEqual(500, captured.exception.status)
        self.assertEqual("SESSION_STORAGE_CORRUPT", captured.exception.code)

    def test_session_keyset_page_is_bounded_and_stable_across_ties_and_delete(self) -> None:
        session_ids = self._seed_sessions()
        statements: list[str] = []
        original_connect = self.backend._connect

        def traced_connection():
            connection = original_connect()
            connection.set_trace_callback(statements.append)
            return connection

        with patch.object(self.backend, "_connect", side_effect=traced_connection):
            first = self.backend.list_sessions()
        self.assertEqual({"sessions", "next_cursor"}, set(first))
        self.assertEqual(50, len(first["sessions"]))
        self.assertIsNotNone(first["next_cursor"])
        expected = sorted(session_ids, reverse=True)
        first_ids = [item["session_id"] for item in first["sessions"]]
        self.assertEqual(expected[:50], first_ids)

        normalized = [" ".join(statement.upper().split()) for statement in statements]
        list_statements = [
            statement for statement in normalized if "FROM SESSIONS AS SESSIONS" in statement
        ]
        self.assertEqual(1, len(list_statements))
        self.assertIn("LEFT JOIN COMPLETIONS", list_statements[0])
        self.assertIn("LIMIT 51", list_statements[0])
        self.assertNotIn("OFFSET", list_statements[0])
        self.assertFalse(
            any("SELECT SESSION_ID,REQUEST_JSON FROM COMPLETIONS" in item for item in normalized)
        )

        with self.backend._connect() as connection:
            connection.execute("DELETE FROM sessions WHERE session_id = ?", (expected[0],))
        second = self.backend.list_sessions(first["next_cursor"])
        second_ids = [item["session_id"] for item in second["sessions"]]
        self.assertEqual(expected[50:], second_ids)
        self.assertFalse(set(first_ids) & set(second_ids))
        self.assertIsNone(second["next_cursor"])

    def test_candidate_keyset_page_uses_only_bounded_head_join_and_exact_summaries(self) -> None:
        session_ids = self._seed_sessions(1)
        session_id = session_ids[0]
        candidates = self._seed_candidates(session_id)
        statements: list[str] = []
        original_connect = self.backend._connect

        def traced_connection():
            connection = original_connect()
            connection.set_trace_callback(statements.append)
            return connection

        with (
            patch.object(self.backend, "_connect", side_effect=traced_connection),
            patch.object(
                self.backend,
                "_candidate_from_connection",
                side_effect=AssertionError("list loaded a full candidate chain"),
            ),
        ):
            first = self.backend.list_candidates(session_id)
            second = self.backend.list_candidates(session_id, first["next_cursor"])

        expected_ids = sorted(candidates)
        first_ids = [item["candidate_id"] for item in first["candidates"]]
        second_ids = [item["candidate_id"] for item in second["candidates"]]
        self.assertEqual(expected_ids[:50], first_ids)
        self.assertEqual(expected_ids[50:], second_ids)
        self.assertFalse(set(first_ids) & set(second_ids))
        self.assertIsNone(second["next_cursor"])
        self.assertTrue(
            all(
                set(item)
                == {
                    "candidate_id",
                    "candidate_version",
                    "candidate_digest",
                    "state",
                    "priority",
                    "title",
                    "summary",
                    "version_created_at",
                }
                for item in first["candidates"] + second["candidates"]
            )
        )

        normalized = [" ".join(statement.upper().split()) for statement in statements]
        list_statements = [
            statement
            for statement in normalized
            if "FROM CANDIDATE_HEADS AS HEADS" in statement
        ]
        self.assertEqual(2, len(list_statements))
        self.assertTrue(all("LEFT JOIN CANDIDATE_VERSIONS" in item for item in list_statements))
        self.assertTrue(all("LIMIT 51" in item for item in list_statements))
        self.assertTrue(all("OFFSET" not in item for item in list_statements))

        transitioned = self._transition_candidate_head(candidates[expected_ids[50]])
        with self.backend._connect() as connection:
            connection.execute(
                "DELETE FROM candidate_heads WHERE candidate_id = ?",
                (expected_ids[51],),
            )
            connection.execute(
                "DELETE FROM candidate_versions WHERE candidate_id = ?",
                (expected_ids[51],),
            )
        changed_second = self.backend.list_candidates(session_id, first["next_cursor"])
        self.assertEqual(1, len(changed_second["candidates"]))
        self.assertEqual(transitioned["candidate_id"], changed_second["candidates"][0]["candidate_id"])
        self.assertEqual(2, changed_second["candidates"][0]["candidate_version"])
        self.assertEqual("needs_clarification", changed_second["candidates"][0]["state"])

    def test_service_rejects_malformed_cross_kind_and_cross_session_cursors(self) -> None:
        session_ids = self._seed_sessions()
        candidates = self._seed_candidates(session_ids[-1])
        session_cursor = self.backend.list_sessions()["next_cursor"]
        candidate_cursor = self.backend.list_candidates(session_ids[-1])["next_cursor"]
        self.assertIsNotNone(session_cursor)
        self.assertIsNotNone(candidate_cursor)
        self.assertEqual(52, len(candidates))

        cases = (
            lambda: self.backend.list_sessions(candidate_cursor),
            lambda: self.backend.list_candidates(session_ids[-1], session_cursor),
            lambda: self.backend.list_candidates(session_ids[-2], candidate_cursor),
            lambda: self.backend.list_sessions("="),
            lambda: self.backend.list_sessions("A"),
            lambda: self.backend.list_sessions("not*base64"),
            lambda: self.backend.list_sessions(
                base64.urlsafe_b64encode(b'{"kind":"sessions"}').rstrip(b"=").decode("ascii")
            ),
            lambda: self.backend.list_sessions("a" * 513),
        )
        for callback in cases:
            with self.subTest(callback=callback), self.assertRaises(ApiError) as captured:
                callback()
            self.assertEqual(400, captured.exception.status)
            self.assertEqual("PAGE_CURSOR_INVALID", captured.exception.code)


class PaginationHTTPTests(PaginationDataMixin, BackendHarness):
    def handler(self, path: str) -> PilotRequestHandler:
        handler = object.__new__(PilotRequestHandler)
        handler.path = path
        handler.command = "GET"
        handler.server = SimpleNamespace(backend=self.backend)
        handler.headers = Message()
        handler.headers["Authorization"] = "Bearer " + self.admin_secret.decode("ascii")
        handler.close_connection = False
        handler.rfile = io.BytesIO()
        handler.wfile = io.BytesIO()
        return handler

    def _dispatch_json(self, path: str, cursor: str | None = None) -> dict:
        handler = self.handler(path)
        if cursor is not None:
            handler.headers["Tacua-Page-Cursor"] = cursor
        sent: list[tuple[int, dict]] = []
        handler._send_json = lambda status, body: sent.append((status, body))
        handler._dispatch()
        self.assertEqual(200, sent[0][0])
        return sent[0][1]

    def test_http_pages_and_strict_cursor_header_rejections(self) -> None:
        session_ids = self._seed_sessions()
        self._seed_candidates(session_ids[-1])
        sessions_first = self._dispatch_json("/v1/admin/sessions")
        sessions_second = self._dispatch_json(
            "/v1/admin/sessions",
            sessions_first["next_cursor"],
        )
        self.assertEqual(50, len(sessions_first["sessions"]))
        self.assertEqual(2, len(sessions_second["sessions"]))

        candidates_path = f"/v1/admin/sessions/{session_ids[-1]}/candidates"
        candidates_first = self._dispatch_json(candidates_path)
        candidates_second = self._dispatch_json(
            candidates_path,
            candidates_first["next_cursor"],
        )
        self.assertEqual(50, len(candidates_first["candidates"]))
        self.assertEqual(2, len(candidates_second["candidates"]))

        invalid_handlers: list[PilotRequestHandler] = []
        duplicate = self.handler("/v1/admin/sessions")
        duplicate.headers.add_header("Tacua-Page-Cursor", sessions_first["next_cursor"])
        duplicate.headers.add_header("Tacua-Page-Cursor", sessions_first["next_cursor"])
        invalid_handlers.append(duplicate)
        empty = self.handler("/v1/admin/sessions")
        empty.headers["Tacua-Page-Cursor"] = ""
        invalid_handlers.append(empty)
        oversized = self.handler("/v1/admin/sessions")
        oversized.headers["Tacua-Page-Cursor"] = "a" * 513
        invalid_handlers.append(oversized)
        malformed = self.handler("/v1/admin/sessions")
        malformed.headers["Tacua-Page-Cursor"] = "not*base64"
        invalid_handlers.append(malformed)
        cross_kind = self.handler("/v1/admin/sessions")
        cross_kind.headers["Tacua-Page-Cursor"] = candidates_first["next_cursor"]
        invalid_handlers.append(cross_kind)
        cross_session = self.handler(
            f"/v1/admin/sessions/{session_ids[-2]}/candidates"
        )
        cross_session.headers["Tacua-Page-Cursor"] = candidates_first["next_cursor"]
        invalid_handlers.append(cross_session)

        for handler in invalid_handlers:
            with self.subTest(path=handler.path), self.assertRaises(ApiError) as captured:
                handler._dispatch()
            self.assertEqual(400, captured.exception.status)
            self.assertEqual("PAGE_CURSOR_INVALID", captured.exception.code)


if __name__ == "__main__":
    unittest.main()
