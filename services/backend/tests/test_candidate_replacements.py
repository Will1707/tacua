# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
from email.message import Message
import io
import json
from pathlib import Path
import sqlite3
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parents[3]
SOURCE = REPOSITORY / "services" / "backend" / "src"
CONTRACT_SOURCE = REPOSITORY / "contracts" / "ticket-candidate" / "src"
TEST_SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE))
sys.path.insert(0, str(CONTRACT_SOURCE))
sys.path.insert(0, str(TEST_SOURCE))

from candidate_replacement_contract import (  # noqa: E402
    validate_replacement_request,
    validate_replacement_response,
)
from tacua_backend.candidate_domain import TICKET_CONTRACT  # noqa: E402
from tacua_backend.candidate_store import CandidateStoreError  # noqa: E402
from tacua_backend.contracts import canonical_json  # noqa: E402
from tacua_backend.evidence_domain import seal_item, seal_manifest, sha256_digest  # noqa: E402
from tacua_backend.http_api import PilotRequestHandler  # noqa: E402
from tacua_backend.service import ApiError  # noqa: E402
from test_backend import BackendHarness  # noqa: E402


class CandidateReplacementTests(BackendHarness):
    @staticmethod
    def binding(candidate: dict) -> dict:
        return {
            "candidate_id": candidate["candidate_id"],
            "candidate_version": candidate["candidate_version"],
            "candidate_digest": candidate["candidate_digest"],
            "candidate_content_digest": candidate["candidate_content_digest"],
            "evidence_manifest_digest": candidate["evidence_manifest"][
                "manifest_digest"
            ],
        }

    @staticmethod
    def result(candidate_id: str, source: dict, title: str) -> dict:
        content = copy.deepcopy(source["content"])
        content["title"] = title
        return {"candidate_id": candidate_id, "content": content}

    def replacement_request(
        self,
        operation: str,
        sources: list[dict],
        results: list[dict],
    ) -> dict:
        request = {
            "operation": operation,
            "actor_id": self.config.reviewer_id,
            "reason": f"reviewer_{operation}_candidate",
            "sources": [self.binding(source) for source in sources],
            "results": copy.deepcopy(results),
        }
        validate_replacement_request(request)
        return request

    def publish_source(self) -> tuple[str, dict, dict, list[dict]]:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.persist_candidate_fixture(
            candidate=candidate,
            evidence_manifest=manifest,
            previews=previews,
        )
        return session_id, candidate, manifest, previews

    def publish_second_source(
        self,
        first: dict,
        first_manifest: dict,
        previews: list[dict],
    ) -> tuple[dict, dict]:
        manifest = copy.deepcopy(first_manifest)
        manifest["manifest_id"] = "manifest_secondary_issue"
        extra = copy.deepcopy(manifest["items"][1])
        extra["evidence_id"] = "evidence_secondary"
        extra["description"] = "Additional repository evidence for the secondary issue."
        extra["source"]["snapshot_revision"] = "snapshot_evidence_secondary"
        extra["reference"]["locator"]["evidence_id"] = "evidence_secondary"
        extra["reference"]["locator"]["revision_id"] = "revision_evidence_secondary"
        extra = seal_item(extra)
        manifest["items"].append(extra)
        manifest = seal_manifest(manifest)

        candidate = copy.deepcopy(first)
        candidate["candidate_id"] = "candidate_secondary_issue"
        candidate["content"]["title"] = "Secondary captured issue"
        candidate["evidence_manifest"] = {
            "manifest_id": manifest["manifest_id"],
            "manifest_digest": manifest["manifest_digest"],
            "evidence_ids": sorted(item["evidence_id"] for item in manifest["items"]),
        }
        candidate = TICKET_CONTRACT.seal(candidate)
        TICKET_CONTRACT.validate_chain([candidate])
        self.persist_candidate_fixture(
            candidate=candidate,
            evidence_manifest=manifest,
            previews=previews,
        )
        return candidate, manifest

    def test_split_is_atomic_persistent_idempotent_and_excludes_source(self) -> None:
        session_id, source, source_manifest, previews = self.publish_source()
        request = self.replacement_request(
            "split",
            [source],
            [
                self.result("candidate_split_copy", source, "Incorrect profile copy"),
                self.result("candidate_split_state", source, "Incorrect profile state"),
            ],
        )

        response = self.backend.replace_candidates(
            idempotency_key="replacement:split:001",
            body=request,
        )
        document = json.loads(response.body)
        validate_replacement_response(document, request=request)
        self.assertEqual(201, response.status)
        self.assertEqual(sha256_digest(response.body), response.body_digest)
        self.assertEqual(
            [result["candidate_id"] for result in request["results"]],
            [candidate["candidate_id"] for candidate in document["candidates"]],
        )
        for candidate in document["candidates"]:
            self.assertEqual("split", candidate["lineage"]["operation"])
            self.assertEqual(source["evidence_manifest"], candidate["evidence_manifest"])
            with self.backend._connect() as connection:
                stored_manifest = self.backend._evidence_store(connection).get_manifest(
                    **self.backend._candidate_binding(candidate)
                )
            self.assertEqual(source_manifest, stored_manifest)
            preview = self.backend.get_candidate_preview(
                candidate["candidate_id"],
                candidate["candidate_version"],
                "evidence_frame",
                candidate_digest=candidate["candidate_digest"],
                manifest_digest=candidate["evidence_manifest"]["manifest_digest"],
            )
            self.assertEqual(
                {**previews[0], "authorized_for_handoff": False},
                preview,
            )

        active = self.backend.list_candidates(session_id)["candidates"]
        self.assertEqual(
            ["candidate_split_copy", "candidate_split_state"],
            [item["candidate_id"] for item in active],
        )
        self.assertEqual(source, self.backend.get_candidate(source["candidate_id"], 1))
        supersession = self.backend.get_candidate_supersession(source["candidate_id"])
        self.assertEqual(document["operation"], supersession["operation"])

        replay = self.backend.replace_candidates(
            idempotency_key="replacement:split:001",
            body=copy.deepcopy(request),
        )
        self.assertEqual(response, replay)
        persisted = self.backend._candidate_store().get_supersession(
            source["candidate_id"]
        )
        self.assertEqual(supersession, persisted)

        first_result = document["candidates"][0]
        advanced = json.loads(
            self.backend.transition_candidate(
                first_result["candidate_id"],
                if_match=first_result["candidate_digest"],
                idempotency_key="transition:replacement-result",
                body=self.candidate_transition_body(
                    first_result, "resolve_clarification"
                ),
            ).body
        )
        self.assertEqual(2, advanced["candidate_version"])
        self.assertEqual(
            response,
            self.backend.replace_candidates(
                idempotency_key="replacement:split:001", body=request
            ),
        )
        self.assertEqual(
            supersession,
            self.backend.get_candidate_supersession(source["candidate_id"]),
        )

        changed = copy.deepcopy(request)
        changed["reason"] = "different_reviewer_reason"
        self.assert_api_error(
            409,
            "IDEMPOTENCY_CONFLICT",
            lambda: self.backend.replace_candidates(
                idempotency_key="replacement:split:001", body=changed
            ),
        )
        conflict = self.assert_api_error(
            409,
            "CANDIDATE_SUPERSEDED",
            lambda: self.backend.transition_candidate(
                source["candidate_id"],
                if_match=source["candidate_digest"],
                idempotency_key="transition:superseded",
                body=self.candidate_transition_body(source, "resolve_clarification"),
            ),
        )
        self.assertEqual(
            {
                "operation_id": document["operation"]["operation_id"],
                "operation": "split",
                "replacements": document["operation"]["results"],
            },
            conflict.details,
        )
        handoff_conflict = self.assert_api_error(
            409,
            "CANDIDATE_SUPERSEDED",
            lambda: self.backend.get_candidate_handoff(source["candidate_id"]),
        )
        self.assertEqual(conflict.details, handoff_conflict.details)

    def test_merge_creates_canonical_union_and_inherits_verified_preview(self) -> None:
        session_id, first, first_manifest, previews = self.publish_source()
        second_previews = copy.deepcopy(previews)
        second_previews[0]["preview_revision_id"] = "preview_secondary"
        second, second_manifest = self.publish_second_source(
            first, first_manifest, second_previews
        )
        request = self.replacement_request(
            "merge",
            [second, first],
            [self.result("candidate_merged_issue", first, "Combined profile issue")],
        )

        outside_union = copy.deepcopy(request)
        outside_union["results"][0]["content"]["summary"]["evidence_refs"].append(
            "evidence_outside_union"
        )
        self.assert_api_error(
            400,
            "INVALID_CANDIDATE_REPLACEMENT_CONTENT",
            lambda: self.backend.replace_candidates(
                idempotency_key="replacement:merge:outside-union",
                body=outside_union,
            ),
        )

        response = self.backend.replace_candidates(
            idempotency_key="replacement:merge:001", body=request
        )
        document = json.loads(response.body)
        validate_replacement_response(document, request=request)
        merged = document["candidates"][0]
        self.assertEqual("merged", merged["lineage"]["operation"])
        self.assertEqual(
            [source["candidate_id"] for source in request["sources"]],
            [parent["candidate_id"] for parent in merged["lineage"]["parents"]],
        )
        evidence = self.backend.get_candidate_evidence(
            merged["candidate_id"],
            1,
            candidate_digest=merged["candidate_digest"],
            manifest_digest=merged["evidence_manifest"]["manifest_digest"],
        )
        expected_ids = sorted(
            {
                item["evidence_id"]
                for manifest in (first_manifest, second_manifest)
                for item in manifest["items"]
            }
        )
        self.assertEqual(expected_ids, merged["evidence_manifest"]["evidence_ids"])
        self.assertEqual(expected_ids, [item["evidence_id"] for item in evidence["items"]])
        preview = self.backend.get_candidate_preview(
            merged["candidate_id"],
            1,
            "evidence_frame",
            candidate_digest=merged["candidate_digest"],
            manifest_digest=merged["evidence_manifest"]["manifest_digest"],
        )
        self.assertEqual(previews[0]["body"], preview["body"])
        self.assertEqual(
            previews[0]["preview_revision_id"], preview["preview_revision_id"]
        )
        resolved = json.loads(
            self.backend.transition_candidate(
                merged["candidate_id"],
                if_match=merged["candidate_digest"],
                idempotency_key="transition:merged:resolve",
                body=self.candidate_transition_body(
                    merged, "resolve_clarification"
                ),
            ).body
        )
        approved = json.loads(
            self.backend.transition_candidate(
                resolved["candidate_id"],
                if_match=resolved["candidate_digest"],
                idempotency_key="transition:merged:approve",
                body=self.candidate_transition_body(resolved, "approve"),
            ).body
        )
        self.assertEqual(
            approved["candidate_digest"],
            self.backend.get_candidate_handoff(approved["candidate_id"]).candidate_digest,
        )
        self.assertEqual(
            ["candidate_merged_issue"],
            [item["candidate_id"] for item in self.backend.list_candidates(session_id)["candidates"]],
        )
        for source in (first, second):
            self.assertEqual(
                document["operation"],
                self.backend.get_candidate_supersession(source["candidate_id"])[
                    "operation"
                ],
            )

    def test_merge_rejects_conflicting_latest_preview_content_metadata(self) -> None:
        session_id, first, first_manifest, previews = self.publish_source()
        second, second_manifest = self.publish_second_source(
            first, first_manifest, previews
        )
        with self.backend._connect() as connection:
            latest = connection.execute(
                """SELECT previews.content_type, previews.size_bytes,
                          previews.relative_path
                     FROM tacua_evidence_manifests AS manifests
                     JOIN tacua_evidence_manifest_items AS membership
                       ON membership.manifest_row_id = manifests.manifest_row_id
                     JOIN tacua_evidence_items AS items
                       ON items.item_row_id = membership.item_row_id
                     JOIN tacua_evidence_preview_revisions AS previews
                       ON previews.manifest_row_id = manifests.manifest_row_id
                      AND previews.item_row_id = items.item_row_id
                    WHERE manifests.manifest_digest = ?
                      AND items.evidence_id = 'evidence_frame'
                    ORDER BY previews.preview_row_id DESC LIMIT 1""",
                (second_manifest["manifest_digest"],),
            ).fetchone()
            self.assertIsNotNone(latest)
            connection.execute(
                """INSERT INTO tacua_evidence_preview_revisions (
                       manifest_row_id, item_row_id, preview_revision_id,
                       availability, content_type, size_bytes, content_digest,
                       relative_path, unavailable_reason, unavailable_detail,
                       recorded_at
                   )
                   SELECT manifests.manifest_row_id, items.item_row_id,
                          'preview_conflicting', 'available', ?, ?, ?, ?,
                          NULL, NULL, '2026-07-21T10:03:00Z'
                     FROM tacua_evidence_manifests AS manifests
                     JOIN tacua_evidence_manifest_items AS membership
                       ON membership.manifest_row_id = manifests.manifest_row_id
                     JOIN tacua_evidence_items AS items
                       ON items.item_row_id = membership.item_row_id
                    WHERE manifests.manifest_digest = ?
                      AND items.evidence_id = 'evidence_frame'""",
                (
                    latest["content_type"],
                    latest["size_bytes"],
                    "sha256:" + "f" * 64,
                    latest["relative_path"],
                    second_manifest["manifest_digest"],
                ),
            )

        request = self.replacement_request(
            "merge",
            [first, second],
            [self.result("candidate_preview_conflict", first, "Preview conflict")],
        )
        self.assert_api_error(
            409,
            "MERGE_PREVIEW_CONFLICT",
            lambda: self.backend.replace_candidates(
                idempotency_key="replacement:merge:preview-conflict",
                body=request,
            ),
        )
        self.assertEqual(
            [first["candidate_id"], second["candidate_id"]],
            [
                item["candidate_id"]
                for item in self.backend.list_candidates(session_id)["candidates"]
            ],
        )

    def test_split_reuses_contract_valid_source_manifest_order_exactly(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        source, manifest, previews = self.candidate_bundle(session_id)
        source["evidence_manifest"]["evidence_ids"] = list(
            reversed(source["evidence_manifest"]["evidence_ids"])
        )
        source = TICKET_CONTRACT.seal(source)
        TICKET_CONTRACT.validate_chain([source])
        self.persist_candidate_fixture(
            candidate=source,
            evidence_manifest=manifest,
            previews=previews,
        )
        request = self.replacement_request(
            "split",
            [source],
            [
                self.result("candidate_order_one", source, "Manifest order issue one"),
                self.result("candidate_order_two", source, "Manifest order issue two"),
            ],
        )
        response = json.loads(
            self.backend.replace_candidates(
                idempotency_key="replacement:split:manifest-order", body=request
            ).body
        )
        validate_replacement_response(response, request=request)
        self.assertTrue(
            all(
                candidate["evidence_manifest"] == source["evidence_manifest"]
                for candidate in response["candidates"]
            )
        )

    def test_stale_authorization_bounds_distinctness_and_scope_fail_closed(self) -> None:
        _, source, _, _ = self.publish_source()
        results = [
            self.result("candidate_split_first", source, "First split issue"),
            self.result("candidate_split_second", source, "Second split issue"),
        ]
        request = self.replacement_request("split", [source], results)

        unauthorized = copy.deepcopy(request)
        unauthorized["actor_id"] = "reviewer_other"
        self.assert_api_error(
            403,
            "REVIEWER_MISMATCH",
            lambda: self.backend.replace_candidates(
                idempotency_key="replacement:unauthorized", body=unauthorized
            ),
        )
        undersized = copy.deepcopy(request)
        undersized["results"] = undersized["results"][:1]
        self.assert_api_error(
            400,
            "INVALID_CANDIDATE_REPLACEMENT_RESULTS",
            lambda: self.backend.replace_candidates(
                idempotency_key="replacement:undersized", body=undersized
            ),
        )
        oversized = copy.deepcopy(request)
        oversized["results"] = [
            self.result(
                f"candidate_excess_{index:02d}",
                source,
                f"Excess split issue {index}",
            )
            for index in range(17)
        ]
        self.assert_api_error(
            400,
            "INVALID_CANDIDATE_REPLACEMENT_RESULTS",
            lambda: self.backend.replace_candidates(
                idempotency_key="replacement:oversized", body=oversized
            ),
        )
        duplicate_content = copy.deepcopy(request)
        duplicate_content["results"][1]["content"] = copy.deepcopy(
            duplicate_content["results"][0]["content"]
        )
        self.assert_api_error(
            409,
            "SPLIT_CONTENT_NOT_DISTINCT",
            lambda: self.backend.replace_candidates(
                idempotency_key="replacement:duplicate-content",
                body=duplicate_content,
            ),
        )
        unchanged = copy.deepcopy(request)
        unchanged["results"][0]["content"] = copy.deepcopy(source["content"])
        self.assert_api_error(
            409,
            "SPLIT_CONTENT_NOT_DISTINCT",
            lambda: self.backend.replace_candidates(
                idempotency_key="replacement:unchanged", body=unchanged
            ),
        )

        stale_mutations = {
            "candidate_version": source["candidate_version"] + 1,
            "candidate_digest": "sha256:" + "c" * 64,
            "candidate_content_digest": "sha256:" + "d" * 64,
            "evidence_manifest_digest": "sha256:" + "e" * 64,
        }
        for index, (field, value) in enumerate(stale_mutations.items()):
            stale = copy.deepcopy(request)
            stale["sources"][0][field] = value
            self.assert_api_error(
                412,
                "CANDIDATE_PRECONDITION_FAILED",
                lambda stale=stale, index=index: self.backend.replace_candidates(
                    idempotency_key=f"replacement:binding:{index}", body=stale
                ),
            )

        resolved = json.loads(
            self.backend.transition_candidate(
                source["candidate_id"],
                if_match=source["candidate_digest"],
                idempotency_key="transition:before-stale-split",
                body=self.candidate_transition_body(source, "resolve_clarification"),
            ).body
        )
        self.assertEqual(2, resolved["candidate_version"])
        self.assert_api_error(
            412,
            "CANDIDATE_PRECONDITION_FAILED",
            lambda: self.backend.replace_candidates(
                idempotency_key="replacement:stale", body=request
            ),
        )
        approved = json.loads(
            self.backend.transition_candidate(
                resolved["candidate_id"],
                if_match=resolved["candidate_digest"],
                idempotency_key="transition:terminal-before-split",
                body=self.candidate_transition_body(resolved, "approve"),
            ).body
        )
        terminal_request = self.replacement_request(
            "split",
            [approved],
            [
                self.result(
                    "candidate_terminal_first", approved, "Terminal split one"
                ),
                self.result(
                    "candidate_terminal_second", approved, "Terminal split two"
                ),
            ],
        )
        self.assert_api_error(
            409,
            "CANDIDATE_NOT_REPLACEABLE",
            lambda: self.backend.replace_candidates(
                idempotency_key="replacement:terminal", body=terminal_request
            ),
        )

    def test_malformed_operation_types_are_stable_client_errors(self) -> None:
        _, source, _, _ = self.publish_source()
        request = self.replacement_request(
            "split",
            [source],
            [
                self.result("candidate_invalid_op_one", source, "Invalid operation one"),
                self.result("candidate_invalid_op_two", source, "Invalid operation two"),
            ],
        )
        malformed_operations = ([], {}, True, None)
        for index, operation in enumerate(malformed_operations):
            malformed = copy.deepcopy(request)
            malformed["operation"] = operation
            self.assert_api_error(
                400,
                "INVALID_CANDIDATE_REPLACEMENT_OPERATION",
                lambda malformed=malformed, index=index: self.backend.replace_candidates(
                    idempotency_key=f"replacement:invalid-operation:domain:{index}",
                    body=malformed,
                ),
            )

            payload = canonical_json(malformed).encode("utf-8")
            handler = object.__new__(PilotRequestHandler)
            handler.path = "/v1/admin/candidate-replacements"
            handler.command = "POST"
            handler.server = SimpleNamespace(backend=self.backend)
            handler.headers = Message()
            handler.headers["Authorization"] = (
                "Bearer " + self.admin_secret.decode("ascii")
            )
            handler.headers["Content-Type"] = "application/json"
            handler.headers["Content-Length"] = str(len(payload))
            handler.headers["Idempotency-Key"] = (
                f"replacement:invalid-operation:http:{index}"
            )
            handler.close_connection = False
            handler.rfile = io.BytesIO(payload)
            handler.wfile = io.BytesIO()
            sent: list[tuple[int, dict]] = []
            handler._send_json = lambda status, body: sent.append((status, body))
            handler._handle()
            self.assertEqual(
                (
                    400,
                    {
                        "error": {
                            "code": "INVALID_CANDIDATE_REPLACEMENT_OPERATION",
                            "message": "candidate replacement operation is invalid",
                        }
                    },
                ),
                sent[0],
            )

    def test_guard_failure_rolls_back_every_replacement_projection(self) -> None:
        session_id, source, _, _ = self.publish_source()
        request = self.replacement_request(
            "split",
            [source],
            [
                self.result("candidate_rollback_one", source, "Rollback issue one"),
                self.result("candidate_rollback_two", source, "Rollback issue two"),
            ],
        )

        def fail_guard(
            connection: sqlite3.Connection,
            operation: str,
            sources: list[dict],
            results: list[dict],
            manifest: dict,
        ) -> None:
            _ = (operation, sources, results, manifest)
            connection.execute("CREATE TABLE replacement_rollback_probe (value TEXT)")
            connection.execute(
                "INSERT INTO replacement_rollback_probe (value) VALUES ('written')"
            )
            raise CandidateStoreError(
                409, "SIMULATED_REPLACEMENT_FAILURE", "simulated guard failure"
            )

        with patch.object(self.backend, "_bind_replacement_results", new=fail_guard):
            self.assert_api_error(
                409,
                "SIMULATED_REPLACEMENT_FAILURE",
                lambda: self.backend.replace_candidates(
                    idempotency_key="replacement:rollback", body=request
                ),
            )
        self.assertEqual(
            [source["candidate_id"]],
            [item["candidate_id"] for item in self.backend.list_candidates(session_id)["candidates"]],
        )
        with self.backend._connect() as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE name = 'replacement_rollback_probe'"
                ).fetchone()
            )
            self.assertEqual(
                (1, 1, 0, 0),
                (
                    connection.execute("SELECT COUNT(*) FROM candidate_versions").fetchone()[0],
                    connection.execute("SELECT COUNT(*) FROM candidate_heads").fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM candidate_replacement_operations"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM candidate_supersessions"
                    ).fetchone()[0],
                ),
            )

    def test_two_replacements_of_one_head_have_exactly_one_atomic_winner(self) -> None:
        session_id, source, _, _ = self.publish_source()
        requests = [
            self.replacement_request(
                "split",
                [source],
                [
                    self.result(
                        f"candidate_race_{attempt}_one",
                        source,
                        f"Race {attempt} issue one",
                    ),
                    self.result(
                        f"candidate_race_{attempt}_two",
                        source,
                        f"Race {attempt} issue two",
                    ),
                ],
            )
            for attempt in range(2)
        ]
        barrier = threading.Barrier(3)
        outcomes: list[tuple[str, object]] = []

        def submit(attempt: int) -> None:
            barrier.wait()
            try:
                response = self.backend.replace_candidates(
                    idempotency_key=f"replacement:race:{attempt}",
                    body=requests[attempt],
                )
                outcomes.append(("success", json.loads(response.body)))
            except ApiError as error:
                outcomes.append(("error", error))

        threads = [threading.Thread(target=submit, args=(attempt,)) for attempt in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())

        self.assertEqual(1, sum(kind == "success" for kind, _ in outcomes))
        errors = [value for kind, value in outcomes if kind == "error"]
        self.assertEqual(1, len(errors))
        self.assertIsInstance(errors[0], ApiError)
        self.assertEqual("CANDIDATE_SUPERSEDED", errors[0].code)
        winner = next(value for kind, value in outcomes if kind == "success")
        self.assertEqual(
            [binding["candidate_id"] for binding in winner["operation"]["results"]],
            [item["candidate_id"] for item in self.backend.list_candidates(session_id)["candidates"]],
        )
        with self.backend._connect() as connection:
            self.assertEqual(
                (1, 1),
                (
                    connection.execute(
                        "SELECT COUNT(*) FROM candidate_replacement_operations"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM candidate_supersessions"
                    ).fetchone()[0],
                ),
            )

    def test_http_routes_return_committed_body_and_supersession_projection(self) -> None:
        _, source, _, _ = self.publish_source()
        request = self.replacement_request(
            "split",
            [source],
            [
                self.result("candidate_http_one", source, "HTTP issue one"),
                self.result("candidate_http_two", source, "HTTP issue two"),
            ],
        )
        payload = canonical_json(request).encode("utf-8")
        handler = object.__new__(PilotRequestHandler)
        handler.path = "/v1/admin/candidate-replacements"
        handler.command = "POST"
        handler.server = SimpleNamespace(backend=self.backend)
        handler.headers = Message()
        handler.headers["Authorization"] = "Bearer " + self.admin_secret.decode("ascii")
        handler.headers["Content-Type"] = "application/json"
        handler.headers["Content-Length"] = str(len(payload))
        handler.headers["Idempotency-Key"] = "replacement:http:001"
        handler.close_connection = False
        handler.rfile = io.BytesIO(payload)
        handler.wfile = io.BytesIO()
        sent: list[tuple[int, bytes, dict[str, str]]] = []
        handler._send_bytes = (
            lambda status, body, content_type="application/json", headers=None: sent.append(
                (status, body, headers or {})
            )
        )
        handler._dispatch()
        document = json.loads(sent[0][1])
        validate_replacement_response(document, request=request)
        self.assertEqual(201, sent[0][0])
        self.assertEqual(sha256_digest(sent[0][1]), sent[0][2]["Tacua-Body-Digest"])

        lookup = object.__new__(PilotRequestHandler)
        lookup.path = f"/v1/admin/candidates/{source['candidate_id']}/supersession"
        lookup.command = "GET"
        lookup.server = SimpleNamespace(backend=self.backend)
        lookup.headers = Message()
        lookup.headers["Authorization"] = "Bearer " + self.admin_secret.decode("ascii")
        lookup.close_connection = False
        lookup.rfile = io.BytesIO()
        lookup.wfile = io.BytesIO()
        looked_up: list[tuple[int, dict]] = []
        lookup._send_json = lambda status, body: looked_up.append((status, body))
        lookup._dispatch()
        self.assertEqual((200, {"operation": document["operation"]}), looked_up[0])

        with self.assertRaises(ApiError) as captured:
            self.backend.transition_candidate(
                source["candidate_id"],
                if_match=source["candidate_digest"],
                idempotency_key="transition:http:superseded",
                body=self.candidate_transition_body(source, "resolve_clarification"),
            )
        serialized: list[tuple[int, dict]] = []
        lookup._send_json = lambda status, body: serialized.append((status, body))
        lookup._send_api_error(captured.exception)
        self.assertEqual(
            {
                "error": {
                    "code": "CANDIDATE_SUPERSEDED",
                    "message": "candidate was replaced by a reviewer operation",
                    "details": {
                        "operation_id": document["operation"]["operation_id"],
                        "operation": "split",
                        "replacements": document["operation"]["results"],
                    },
                }
            },
            serialized[0][1],
        )

    def test_replacement_storage_tampering_is_detected_and_session_erasure_cascades(
        self,
    ) -> None:
        session_id, source, _, _ = self.publish_source()
        request = self.replacement_request(
            "split",
            [source],
            [
                self.result("candidate_tamper_one", source, "Tamper issue one"),
                self.result("candidate_tamper_two", source, "Tamper issue two"),
            ],
        )
        self.backend.replace_candidates(
            idempotency_key="replacement:tamper", body=request
        )
        with self.backend._connect() as connection:
            connection.execute(
                """UPDATE candidate_replacement_operations
                      SET operation_json = ?""",
                ('{"changed":true}',),
            )
        self.assert_api_error(
            500,
            "CANDIDATE_STORAGE_CORRUPT",
            lambda: self.backend.get_candidate_supersession(source["candidate_id"]),
        )

        # Restore only the operation projection from its sealed response so the
        # normal deletion path can prove every relationship cascades.
        with self.backend._connect() as connection:
            row = connection.execute(
                "SELECT response_body FROM candidate_replacement_operations"
            ).fetchone()
            operation = json.loads(bytes(row[0]))["operation"]
            connection.execute(
                "UPDATE candidate_replacement_operations SET operation_json = ?",
                (canonical_json(operation),),
            )
        self.backend.delete_session(session_id)
        with self.backend._connect() as connection:
            self.assertEqual(
                (0, 0, 0, 0),
                (
                    connection.execute("SELECT COUNT(*) FROM candidate_versions").fetchone()[0],
                    connection.execute("SELECT COUNT(*) FROM candidate_heads").fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM candidate_replacement_operations"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM candidate_supersessions"
                    ).fetchone()[0],
                ),
            )


if __name__ == "__main__":
    unittest.main()
