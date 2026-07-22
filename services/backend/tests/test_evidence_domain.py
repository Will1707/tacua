# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE = REPOSITORY_ROOT / "services" / "backend" / "src"
sys.path.insert(0, str(SOURCE))

from tacua_backend.evidence_domain import (  # noqa: E402
    EvidenceDomainError,
    EvidenceStore,
    ITEM_VERSION,
    MANIFEST_MEDIA_TYPE,
    MANIFEST_VERSION,
    MAX_PREVIEW_BYTES,
    canonical_json,
    initialize_schema,
    seal_item,
    seal_manifest,
    sha256_digest,
)


ORG = "org_example"
PROJECT = "project_mobile"
SESSION = "session_review"
CANDIDATE = "candidate_copy"
CANDIDATE_DIGEST = "sha256:" + "9" * 64
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "YAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)


class SimulatedProcessCrash(BaseException):
    pass


def available_item(
    evidence_id: str,
    evidence_type: str,
    component: str,
    content_type: str,
    *,
    description: str | None = None,
    start_ms: int | None = 100,
) -> dict:
    reference_size = len(PNG) if evidence_type == "media.keyframe" else 123
    reference_digest = (
        sha256_digest(PNG) if evidence_type == "media.keyframe" else "sha256:" + "4" * 64
    )
    raw = {
        "contract_version": ITEM_VERSION,
        "organization_id": ORG,
        "project_id": PROJECT,
        "session_id": SESSION,
        "evidence_id": evidence_id,
        "evidence_type": evidence_type,
        "availability": "available",
        "description": description or f"Bound metadata for {evidence_id}.",
        "time_range": None
        if start_ms is None
        else {
            "start_ms": start_ms,
            "end_ms": start_ms + 20,
            "clock": "session_monotonic",
        },
        "source": {
            "component": component,
            "source_id": {
                "mobile_sdk": "sdk_session",
                "repository": "repo_mobile",
                "backend": "backend_qa",
                "sentry": "sentry_project",
                "posthog": "posthog_project",
            }[component],
            "snapshot_revision": f"snapshot-{evidence_id}",
            "captured_at": "2026-07-21T10:00:01Z",
        },
        "reference": {
            "locator": {
                "scheme": "tacua-evidence",
                "organization_id": ORG,
                "project_id": PROJECT,
                "evidence_id": evidence_id,
                "revision_id": f"revision_{evidence_id.removeprefix('evidence_')}",
            },
            "content_type": content_type,
            "size_bytes": reference_size,
            "content_digest": reference_digest,
        },
        "unavailable": None,
        "evidence_item_digest": "sha256:" + "0" * 64,
    }
    return seal_item(raw)


def unavailable_item(
    evidence_id: str, evidence_type: str, component: str
) -> dict:
    raw = {
        "contract_version": ITEM_VERSION,
        "organization_id": ORG,
        "project_id": PROJECT,
        "session_id": SESSION,
        "evidence_id": evidence_id,
        "evidence_type": evidence_type,
        "availability": "unavailable",
        "description": f"Collection status for {evidence_id}.",
        "time_range": {
            "start_ms": 0,
            "end_ms": 500,
            "clock": "session_monotonic",
        },
        "source": {
            "component": component,
            "source_id": f"{component}_project",
            "snapshot_revision": f"unavailable-{evidence_id}",
            "captured_at": "2026-07-21T10:00:02Z",
        },
        "reference": None,
        "unavailable": {
            "reason": "correlation_missing",
            "detail": "No matching event was found inside the bounded session window.",
        },
        "evidence_item_digest": "sha256:" + "0" * 64,
    }
    return seal_item(raw)


def manifest() -> dict:
    return seal_manifest(
        {
            "contract_version": MANIFEST_VERSION,
            "media_type": MANIFEST_MEDIA_TYPE,
            "organization_id": ORG,
            "project_id": PROJECT,
            "session_id": SESSION,
            "manifest_id": "manifest_candidate",
            "items": [
                available_item(
                    "evidence_route",
                    "sdk.route_transition",
                    "mobile_sdk",
                    "application/vnd.tacua.sdk-event+json",
                ),
                available_item(
                    "evidence_keyframe",
                    "media.keyframe",
                    "mobile_sdk",
                    "image/png",
                    description="SENTINEL-DESCRIPTION visible screenshot metadata.",
                    start_ms=3900,
                ),
                available_item(
                    "evidence_transcript",
                    "media.transcript_excerpt",
                    "mobile_sdk",
                    "text/plain",
                    start_ms=3800,
                ),
                available_item(
                    "evidence_repository",
                    "repository.commit_snapshot",
                    "repository",
                    "application/vnd.tacua.connector-snapshot+json",
                    start_ms=None,
                ),
                unavailable_item(
                    "evidence_sentry",
                    "observability.sentry_snapshot",
                    "sentry",
                ),
                unavailable_item(
                    "evidence_posthog",
                    "observability.posthog_snapshot",
                    "posthog",
                ),
            ],
            "manifest_digest": "sha256:" + "0" * 64,
        }
    )


class EvidenceDomainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "derived"
        self.connection = sqlite3.connect(":memory:")
        initialize_schema(self.connection)
        self.store = EvidenceStore(self.connection, self.root)
        self.manifest = manifest()
        self.binding = {
            "organization_id": ORG,
            "project_id": PROJECT,
            "session_id": SESSION,
            "candidate_id": CANDIDATE,
            "candidate_version": 1,
            "candidate_digest": CANDIDATE_DIGEST,
            "manifest_digest": self.manifest["manifest_digest"],
        }

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary.cleanup()

    def assert_error(self, code: str, callback) -> EvidenceDomainError:
        with self.assertRaises(EvidenceDomainError) as caught:
            callback()
        self.assertEqual(code, caught.exception.code)
        return caught.exception

    def put_manifest(self, **overrides: object) -> dict:
        values = dict(self.binding)
        values.pop("manifest_digest")
        values.update(overrides)
        return self.store.put_manifest(manifest=self.manifest, **values)

    def put_preview(self, **overrides: object) -> dict:
        values = {
            **self.binding,
            "evidence_id": "evidence_keyframe",
            "preview_revision_id": "preview_primary",
            "content_type": "image/png",
            "size_bytes": len(PNG),
            "content_digest": sha256_digest(PNG),
            "body": PNG,
        }
        values.update(overrides)
        return self.store.put_preview(**values)

    def test_valid_manifest_lookup_preview_and_reviewer_projection(self) -> None:
        created = self.put_manifest()
        self.assertTrue(created["created_manifest"])
        self.assertTrue(created["created_binding"])
        self.assertFalse(created["authorized_for_handoff"])
        retry = self.put_manifest()
        self.assertFalse(retry["created_manifest"])
        self.assertFalse(retry["created_binding"])

        loaded = self.store.get_manifest(**self.binding)
        self.assertEqual(canonical_json(self.manifest), canonical_json(loaded))
        self.assertEqual(
            {
                "sdk.route_transition",
                "media.keyframe",
                "media.transcript_excerpt",
                "repository.commit_snapshot",
                "observability.sentry_snapshot",
                "observability.posthog_snapshot",
            },
            {item["evidence_type"] for item in loaded["items"]},
        )
        self.put_preview()
        preview = self.store.get_preview(
            evidence_id="evidence_keyframe", **self.binding
        )
        self.assertEqual(PNG, preview["body"])
        self.assertEqual("image/png", preview["content_type"])
        self.assertFalse(preview["authorized_for_handoff"])

        events = [
            {
                "event_id": "event_route",
                "sequence": 1,
                "elapsed_ms": 100,
                "occurred_at": "2026-07-21T10:00:01Z",
                "source": "mobile_sdk",
                "event_type": "route_transition",
                "data": {
                    "from_route": None,
                    "to_route": "Settings",
                    "trigger": "user",
                },
                "evidence_refs": ["evidence_route"],
            }
        ]
        view = self.store.get_candidate_evidence_view(
            diagnostic_events=events, **self.binding
        )
        self.assertEqual(
            "tacua.candidate-evidence-view@1.0.0",
            view["contract_version"],
        )
        self.assertEqual(CANDIDATE_DIGEST, view["candidate_digest"])
        self.assertEqual(events, view["diagnostic_events"])
        keyframe = next(
            item
            for item in view["items"]
            if item["evidence_id"] == "evidence_keyframe"
        )
        self.assertEqual("available", keyframe["preview"]["status"])
        self.assertNotIn("locator", keyframe["reference"])
        self.assertNotIn("authorization", keyframe)

    def test_exact_candidate_and_manifest_bindings_are_required(self) -> None:
        self.put_manifest()
        mutations = {
            "organization_id": "org_other",
            "project_id": "project_other",
            "session_id": "session_other",
            "candidate_id": "candidate_other",
            "candidate_version": 2,
            "candidate_digest": "sha256:" + "8" * 64,
            "manifest_digest": "sha256:" + "7" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                binding = dict(self.binding)
                binding[field] = value
                self.assert_error(
                    "EVIDENCE_BINDING_NOT_FOUND",
                    lambda binding=binding: self.store.get_manifest(**binding),
                )

    def test_candidate_review_rejects_handoff_authorization(self) -> None:
        unauthorized = copy.deepcopy(self.manifest)
        unauthorized["items"][0]["authorization"] = {
            "authorized_for_handoff": True
        }
        unauthorized = seal_manifest(unauthorized)
        self.manifest = unauthorized
        error = self.assert_error("FIELDS_INVALID", self.put_manifest)
        self.assertIn("items[0]", error.path)

    def test_database_and_preview_tampering_fail_closed(self) -> None:
        self.put_manifest()
        self.put_preview()
        row = self.connection.execute(
            "SELECT relative_path FROM tacua_evidence_preview_revisions"
        ).fetchone()
        (self.root / row[0]).write_bytes(PNG + b"tampered")
        self.assert_error(
            "STORED_PREVIEW_TAMPERED",
            lambda: self.store.get_preview(
                evidence_id="evidence_keyframe", **self.binding
            ),
        )

        tampered = copy.deepcopy(self.manifest)
        tampered["items"][0]["description"] = "Changed after persistence."
        self.connection.execute(
            "UPDATE tacua_evidence_manifests SET manifest_json = ?",
            (canonical_json(tampered),),
        )
        self.assert_error(
            "STORED_MANIFEST_TAMPERED",
            lambda: self.store.get_manifest(**self.binding),
        )

    def test_coherent_preview_replacement_cannot_escape_manifest_binding(self) -> None:
        self.put_manifest()
        self.put_preview()
        other_png = b"\x89PNG\r\n\x1a\ncoherent-replacement"
        replacement_digest = sha256_digest(other_png)
        relative_path = self.connection.execute(
            "SELECT relative_path FROM tacua_evidence_preview_revisions"
        ).fetchone()[0]
        (self.root / relative_path).write_bytes(other_png)
        with self.connection:
            self.connection.execute(
                """
                UPDATE tacua_evidence_preview_revisions
                   SET size_bytes = ?, content_digest = ?
                """,
                (len(other_png), replacement_digest),
            )

        self.assert_error(
            "STORED_PREVIEW_TAMPERED",
            lambda: self.store.get_preview(
                evidence_id="evidence_keyframe", **self.binding
            ),
        )
        self.assert_error(
            "STORED_PREVIEW_TAMPERED",
            lambda: self.store.get_verified_keyframes_for_approval(
                evidence_ids=["evidence_keyframe"], **self.binding
            ),
        )

    def test_preview_traversal_and_symlink_paths_are_rejected(self) -> None:
        self.put_manifest()
        self.assert_error(
            "IDENTIFIER_INVALID",
            lambda: self.put_preview(preview_revision_id="../escape"),
        )

        parent = (
            self.root
            / "sessions"
            / SESSION
            / "manifests"
            / self.manifest["manifest_digest"].removeprefix("sha256:")
            / "items"
        )
        parent.mkdir(parents=True)
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        os.symlink(outside, parent / "evidence_keyframe")
        self.assert_error("PREVIEW_PATH_SYMLINK", self.put_preview)
        self.assertEqual([], list(outside.iterdir()))

    def test_symlink_root_is_rejected(self) -> None:
        actual = Path(self.temporary.name) / "actual-root"
        actual.mkdir()
        linked = Path(self.temporary.name) / "linked-root"
        os.symlink(actual, linked)
        self.assert_error(
            "EVIDENCE_ROOT_SYMLINK",
            lambda: EvidenceStore(self.connection, linked),
        )

    def test_preview_size_digest_mime_and_signature_are_strict(self) -> None:
        self.put_manifest()
        too_large = b"\x89PNG\r\n\x1a\n" + b"x" * MAX_PREVIEW_BYTES
        self.assert_error(
            "INTEGER_INVALID",
            lambda: self.put_preview(
                body=too_large,
                size_bytes=len(too_large),
                content_digest=sha256_digest(too_large),
            ),
        )
        self.assert_error(
            "PREVIEW_MIME_TYPE_INVALID",
            lambda: self.put_preview(content_type="image/gif"),
        )
        self.assert_error(
            "PREVIEW_SIZE_MISMATCH",
            lambda: self.put_preview(size_bytes=len(PNG) - 1),
        )
        self.assert_error(
            "PREVIEW_DIGEST_MISMATCH",
            lambda: self.put_preview(content_digest="sha256:" + "1" * 64),
        )
        self.assert_error(
            "PREVIEW_SIGNATURE_MISMATCH",
            lambda: self.put_preview(
                body=b"not a png",
                size_bytes=9,
                content_digest=sha256_digest(b"not a png"),
            ),
        )

    def test_preview_must_match_the_sealed_keyframe_reference(self) -> None:
        self.put_manifest()
        other_png = b"\x89PNG\r\n\x1a\nother-keyframe"
        self.assert_error(
            "PREVIEW_REFERENCE_MISMATCH",
            lambda: self.put_preview(
                preview_revision_id="preview_other_keyframe",
                body=other_png,
                size_bytes=len(other_png),
                content_digest=sha256_digest(other_png),
            ),
        )
        jpeg = b"\xff\xd8\xffdifferent-keyframe\xff\xd9"
        self.assert_error(
            "PREVIEW_REFERENCE_MISMATCH",
            lambda: self.put_preview(
                preview_revision_id="preview_wrong_type",
                content_type="image/jpeg",
                body=jpeg,
                size_bytes=len(jpeg),
                content_digest=sha256_digest(jpeg),
            ),
        )
        self.assertEqual(
            0,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_preview_revisions"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_file_journal"
            ).fetchone()[0],
        )

    def test_preview_transaction_guard_runs_inside_both_durable_phases(self) -> None:
        self.put_manifest()
        observed: list[tuple[int, int]] = []

        def guard(connection: sqlite3.Connection) -> None:
            self.assertTrue(connection.in_transaction)
            observed.append(
                (
                    connection.execute(
                        "SELECT COUNT(*) FROM tacua_evidence_file_journal"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM tacua_evidence_preview_revisions"
                    ).fetchone()[0],
                )
            )

        created = self.put_preview(transaction_guard=guard)
        self.assertTrue(created["created"])
        self.assertEqual([(0, 0), (1, 0)], observed)

    def test_preview_transaction_guard_failures_are_atomic_and_recoverable(self) -> None:
        self.put_manifest()

        def reject_first_phase(connection: sqlite3.Connection) -> None:
            self.assertTrue(connection.in_transaction)
            raise EvidenceDomainError(
                "SESSION_PUBLICATION_CLOSED",
                "$.session_id",
                "session no longer accepts evidence publication",
            )

        self.assert_error(
            "SESSION_PUBLICATION_CLOSED",
            lambda: self.put_preview(transaction_guard=reject_first_phase),
        )
        self.assertEqual([], [path for path in self.root.rglob("*") if path.is_file()])
        for table in (
            "tacua_evidence_file_journal",
            "tacua_evidence_preview_revisions",
        ):
            self.assertEqual(
                0,
                self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
            )

        guard_calls = 0

        def crash_second_phase(connection: sqlite3.Connection) -> None:
            nonlocal guard_calls
            self.assertTrue(connection.in_transaction)
            guard_calls += 1
            if guard_calls == 2:
                raise SimulatedProcessCrash()

        with self.assertRaises(SimulatedProcessCrash):
            self.put_preview(transaction_guard=crash_second_phase)
        self.assertEqual(2, guard_calls)
        self.assertEqual(
            1,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_file_journal"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_preview_revisions"
            ).fetchone()[0],
        )
        self.assertEqual(1, len([path for path in self.root.rglob("*") if path.is_file()]))

        recovered = EvidenceStore(self.connection, self.root)
        report = recovered.recover_file_journal()
        self.assertEqual(1, report["journal_entries"])
        self.assertEqual(1, report["preview_files_removed"])
        self.assertEqual([], [path for path in self.root.rglob("*") if path.is_file()])

    def test_preview_phase_two_rechecks_publication_guard_across_file_gap(self) -> None:
        self.put_manifest()
        with self.connection:
            self.connection.execute(
                "CREATE TABLE publication_lease (active INTEGER NOT NULL)"
            )
            self.connection.execute(
                "INSERT INTO publication_lease (active) VALUES (1)"
            )

        def guard(connection: sqlite3.Connection) -> None:
            self.assertTrue(connection.in_transaction)
            active = connection.execute(
                "SELECT active FROM publication_lease"
            ).fetchone()[0]
            if active != 1:
                raise EvidenceDomainError(
                    "SESSION_PUBLICATION_CLOSED",
                    "$.session_id",
                    "session stopped accepting evidence during publication",
                )

        original_write = self.store._write

        def close_publication_after_write(relative_path, staging_relative_path, body):
            target = original_write(relative_path, staging_relative_path, body)
            with self.connection:
                self.connection.execute("UPDATE publication_lease SET active = 0")
            return target

        self.store._write = close_publication_after_write
        self.assert_error(
            "SESSION_PUBLICATION_CLOSED",
            lambda: self.put_preview(transaction_guard=guard),
        )
        self.assertEqual([], [path for path in self.root.rglob("*") if path.is_file()])
        for table in (
            "tacua_evidence_file_journal",
            "tacua_evidence_preview_revisions",
        ):
            self.assertEqual(
                0,
                self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
            )

    def test_manifest_and_item_revisions_are_append_only(self) -> None:
        self.put_manifest()
        changed_manifest = copy.deepcopy(self.manifest)
        changed_manifest["items"][0]["description"] = "New manifest metadata."
        changed_manifest = seal_manifest(changed_manifest)
        original = self.manifest
        self.manifest = changed_manifest
        self.assert_error(
            "EVIDENCE_MANIFEST_REVISION_COLLISION",
            lambda: self.put_manifest(
                candidate_version=2,
                candidate_digest="sha256:" + "8" * 64,
            ),
        )

        changed_item = copy.deepcopy(original)
        changed_item["manifest_id"] = "manifest_second"
        changed_item["items"][0]["description"] = "Changed immutable item revision."
        changed_item = seal_manifest(changed_item)
        self.manifest = changed_item
        self.assert_error(
            "EVIDENCE_ITEM_REVISION_COLLISION",
            lambda: self.put_manifest(
                candidate_version=2,
                candidate_digest="sha256:" + "8" * 64,
            ),
        )

    def test_preview_revision_collision_is_append_only(self) -> None:
        self.put_manifest()
        self.put_preview()
        self.assertFalse(self.put_preview()["created"])
        other = b"\x89PNG\r\n\x1a\nother"
        self.assert_error(
            "PREVIEW_REVISION_COLLISION",
            lambda: self.put_preview(
                body=other,
                size_bytes=len(other),
                content_digest=sha256_digest(other),
            ),
        )

    def test_preview_write_crash_is_recovered_without_an_orphan(self) -> None:
        self.put_manifest()
        original_write = self.store._write

        def crash_after_write(relative_path, staging_relative_path, body):
            original_write(relative_path, staging_relative_path, body)
            raise SimulatedProcessCrash()

        self.store._write = crash_after_write
        with self.assertRaises(SimulatedProcessCrash):
            self.put_preview()
        self.assertEqual(
            1,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_file_journal"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_preview_revisions"
            ).fetchone()[0],
        )
        self.assertEqual(1, len([path for path in self.root.rglob("*") if path.is_file()]))

        recovered = EvidenceStore(self.connection, self.root)
        report = recovered.recover_file_journal()
        self.assertEqual(1, report["journal_entries"])
        self.assertEqual(1, report["preview_files_removed"])
        self.assertEqual([], [path for path in self.root.rglob("*") if path.is_file()])
        self.store = recovered
        self.assertTrue(self.put_preview()["created"])

    def test_file_journal_survives_database_connection_restart(self) -> None:
        database = Path(self.temporary.name) / "evidence.sqlite3"
        root = Path(self.temporary.name) / "restart-derived"
        connection = sqlite3.connect(database)
        initialize_schema(connection)
        store = EvidenceStore(connection, root)
        values = dict(self.binding)
        values.pop("manifest_digest")
        store.put_manifest(manifest=self.manifest, **values)
        original_write = store._write

        def crash_after_write(relative_path, staging_relative_path, body):
            original_write(relative_path, staging_relative_path, body)
            raise SimulatedProcessCrash()

        store._write = crash_after_write
        with self.assertRaises(SimulatedProcessCrash):
            store.put_preview(
                evidence_id="evidence_keyframe",
                preview_revision_id="preview_restart",
                content_type="image/png",
                size_bytes=len(PNG),
                content_digest=sha256_digest(PNG),
                body=PNG,
                **self.binding,
            )
        connection.close()

        recovered_connection = sqlite3.connect(database)
        try:
            recovered = EvidenceStore(recovered_connection, root)
            report = recovered.recover_file_journal()
            self.assertEqual(1, report["journal_entries"])
            self.assertEqual(1, report["preview_files_removed"])
            self.assertEqual(
                0,
                recovered_connection.execute(
                    "SELECT COUNT(*) FROM tacua_evidence_file_journal"
                ).fetchone()[0],
            )
            self.assertEqual([], [path for path in root.rglob("*") if path.is_file()])
        finally:
            recovered_connection.close()

    def test_recovery_preserves_a_committed_verified_preview(self) -> None:
        self.put_manifest()
        self.put_preview()
        row = self.connection.execute(
            """
            SELECT relative_path, content_type, size_bytes, content_digest
              FROM tacua_evidence_preview_revisions
            """
        ).fetchone()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO tacua_evidence_file_journal (
                    operation_id, disposition, relative_path,
                    staging_relative_path, content_type, size_bytes,
                    content_digest, recorded_at
                ) VALUES (?, 'discard_uncommitted_preview', ?, NULL, ?, ?, ?, ?)
                """,
                (
                    "preview_recover_ambiguous",
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    "2026-07-21T10:00:03Z",
                ),
            )
        report = self.store.recover_file_journal()
        self.assertEqual(1, report["committed_previews_preserved"])
        self.assertEqual(PNG, self.store.get_preview(
            evidence_id="evidence_keyframe", **self.binding
        )["body"])

    def test_recovery_refuses_a_forged_cleanup_for_an_active_preview(self) -> None:
        self.put_manifest()
        self.put_preview()
        row = self.connection.execute(
            """
            SELECT relative_path, content_type, size_bytes, content_digest
              FROM tacua_evidence_preview_revisions
            """
        ).fetchone()
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO tacua_evidence_file_journal (
                    operation_id, disposition, relative_path,
                    staging_relative_path, content_type, size_bytes,
                    content_digest, recorded_at
                ) VALUES (?, 'delete_committed_preview', ?, NULL, ?, ?, ?, ?)
                """,
                (
                    "preview_forged_cleanup",
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    "2026-07-21T10:00:03Z",
                ),
            )
        self.assert_error(
            "FILE_JOURNAL_INVALID", self.store.recover_file_journal
        )
        self.assertEqual(
            PNG,
            self.store.get_preview(
                evidence_id="evidence_keyframe", **self.binding
            )["body"],
        )

    def test_approval_keyframes_are_reverified_without_changing_reviewer_view(self) -> None:
        self.put_manifest()
        self.put_preview()
        verified = self.store.get_verified_keyframes_for_approval(
            evidence_ids=["evidence_keyframe"], **self.binding
        )
        self.assertEqual(PNG, verified["verified_keyframes"][0]["body"])
        self.assertEqual(
            sha256_digest(PNG),
            verified["verified_keyframes"][0]["content_digest"],
        )
        self.assertFalse(verified["authorized_for_handoff"])

        relative_path = self.connection.execute(
            "SELECT relative_path FROM tacua_evidence_preview_revisions"
        ).fetchone()[0]
        (self.root / relative_path).write_bytes(PNG + b"tampered")
        view = self.store.get_candidate_evidence_view(
            diagnostic_events=[], **self.binding
        )
        keyframe = next(
            item
            for item in view["items"]
            if item["evidence_id"] == "evidence_keyframe"
        )
        self.assertEqual("available", keyframe["preview"]["status"])
        self.assert_error(
            "STORED_PREVIEW_TAMPERED",
            lambda: self.store.get_verified_keyframes_for_approval(
                evidence_ids=["evidence_keyframe"], **self.binding
            ),
        )
        self.assert_error(
            "APPROVAL_KEYFRAME_INVALID",
            lambda: self.store.get_verified_keyframes_for_approval(
                evidence_ids=["evidence_route"], **self.binding
            ),
        )
        self.assert_error(
            "APPROVAL_KEYFRAMES_INVALID",
            lambda: self.store.get_verified_keyframes_for_approval(
                evidence_ids=["evidence_keyframe", "evidence_keyframe"],
                **self.binding,
            ),
        )

    def test_retention_expiry_preserves_manifest_metadata(self) -> None:
        self.put_manifest()
        self.put_preview()
        before = self.store.get_manifest(**self.binding)
        expired = self.store.mark_preview_unavailable(
            evidence_id="evidence_keyframe",
            preview_revision_id="preview_expired",
            reason="outside_retention",
            detail="Derived preview passed the configured retention deadline.",
            **self.binding,
        )
        self.assertEqual(1, expired["removed_preview_files"])
        self.assertTrue(expired["created"])
        self.assertEqual(before, self.store.get_manifest(**self.binding))
        self.assert_error(
            "PREVIEW_UNAVAILABLE",
            lambda: self.store.get_preview(
                evidence_id="evidence_keyframe", **self.binding
            ),
        )
        view = self.store.get_candidate_evidence_view(
            diagnostic_events=[], **self.binding
        )
        keyframe = next(
            item
            for item in view["items"]
            if item["evidence_id"] == "evidence_keyframe"
        )
        self.assertEqual("unavailable", keyframe["preview"]["status"])
        retry = self.store.mark_preview_unavailable(
            evidence_id="evidence_keyframe",
            preview_revision_id="preview_expired",
            reason="outside_retention",
            detail="Derived preview passed the configured retention deadline.",
            **self.binding,
        )
        self.assertFalse(retry["created"])
        self.assertEqual(0, retry["removed_preview_files"])

    def test_retirement_crash_cannot_leave_an_available_view_with_missing_bytes(self) -> None:
        self.put_manifest()
        self.put_preview()
        original_clear = self.store._clear_journal_row

        def crash_before_journal_clear(journal_row_id):
            raise SimulatedProcessCrash()

        self.store._clear_journal_row = crash_before_journal_clear
        with self.assertRaises(SimulatedProcessCrash):
            self.store.mark_preview_unavailable(
                evidence_id="evidence_keyframe",
                preview_revision_id="preview_expired",
                reason="outside_retention",
                detail="Derived preview passed the configured retention deadline.",
                **self.binding,
            )
        row = self.connection.execute(
            """
            SELECT availability FROM tacua_evidence_preview_revisions
             ORDER BY preview_row_id DESC LIMIT 1
            """
        ).fetchone()
        self.assertEqual(("unavailable",), tuple(row))
        self.assertEqual(
            1,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_file_journal"
            ).fetchone()[0],
        )
        self.assert_error(
            "PREVIEW_UNAVAILABLE",
            lambda: self.store.get_preview(
                evidence_id="evidence_keyframe", **self.binding
            ),
        )

        self.store._clear_journal_row = original_clear
        report = self.store.recover_file_journal()
        self.assertEqual(1, report["journal_entries"])
        self.assertEqual(0, report["preview_files_removed"])
        self.assertEqual(
            0,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_file_journal"
            ).fetchone()[0],
        )

    def test_session_deletion_removes_rows_and_files_idempotently(self) -> None:
        self.put_manifest()
        self.put_preview()
        self.store.put_manifest(
            organization_id=ORG,
            project_id=PROJECT,
            session_id=SESSION,
            candidate_id=CANDIDATE,
            candidate_version=2,
            candidate_digest="sha256:" + "8" * 64,
            manifest=self.manifest,
        )
        session_root = self.root / "sessions" / SESSION
        self.assertTrue(session_root.is_dir())
        orphan = session_root / "orphaned-staging" / "partial-upload.bin"
        orphan.parent.mkdir()
        orphan.write_bytes(b"partial")
        report = self.store.delete_session(
            organization_id=ORG, project_id=PROJECT, session_id=SESSION
        )
        self.assertEqual(
            {
                "candidate_bindings": 2,
                "manifests": 1,
                "manifest_items": 6,
                "items": 6,
                "preview_revisions": 1,
                "preview_files": 1,
            },
            report,
        )
        self.assertFalse(session_root.exists())
        for table in (
            "tacua_candidate_evidence_bindings",
            "tacua_evidence_manifests",
            "tacua_evidence_manifest_items",
            "tacua_evidence_items",
            "tacua_evidence_preview_revisions",
        ):
            self.assertEqual(
                0,
                self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
            )
        self.assertEqual(
            {
                "candidate_bindings": 0,
                "manifests": 0,
                "manifest_items": 0,
                "items": 0,
                "preview_revisions": 0,
                "preview_files": 0,
            },
            self.store.delete_session(
                organization_id=ORG, project_id=PROJECT, session_id=SESSION
            ),
        )
        self.assertFalse(session_root.exists())
        self.assertEqual(
            0,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_directory_journal"
            ).fetchone()[0],
        )

    def test_session_tree_pruning_refuses_symlinks_without_following_them(self) -> None:
        self.put_manifest()
        self.put_preview()
        outside = Path(self.temporary.name) / "outside-session-evidence.txt"
        outside.write_text("must survive", encoding="utf-8")
        session_root = self.root / "sessions" / SESSION
        os.symlink(outside, session_root / "untrusted-link")

        self.assert_error(
            "SESSION_TREE_PATH_SYMLINK",
            lambda: self.store.delete_session(
                organization_id=ORG, project_id=PROJECT, session_id=SESSION
            ),
        )
        self.assertEqual("must survive", outside.read_text(encoding="utf-8"))
        self.assertTrue((session_root / "untrusted-link").is_symlink())
        self.assertEqual(
            1,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_directory_journal"
            ).fetchone()[0],
        )

    def test_session_deletion_crash_is_recoverable_after_metadata_commit(self) -> None:
        self.put_manifest()
        self.put_preview()
        original_drain = self.store._drain_file_journal

        def crash_before_file_cleanup(operation_id=None):
            raise SimulatedProcessCrash()

        self.store._drain_file_journal = crash_before_file_cleanup
        with self.assertRaises(SimulatedProcessCrash):
            self.store.delete_session(
                organization_id=ORG, project_id=PROJECT, session_id=SESSION
            )
        self.assertEqual(
            0,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_candidate_evidence_bindings"
            ).fetchone()[0],
        )
        self.assertEqual(
            1,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_file_journal"
            ).fetchone()[0],
        )
        self.assertEqual(
            1,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_directory_journal"
            ).fetchone()[0],
        )
        self.assertEqual(1, len([path for path in self.root.rglob("*") if path.is_file()]))

        self.store._drain_file_journal = original_drain
        report = self.store.recover_file_journal()
        self.assertEqual(1, report["preview_files_removed"])
        self.assertEqual([], [path for path in self.root.rglob("*") if path.is_file()])
        self.assertFalse((self.root / "sessions" / SESSION).exists())
        self.assertEqual(1, report["directory_journal_entries"])
        self.assertEqual(1, report["session_trees_pruned"])

    def test_session_tree_prune_journal_survives_database_restart(self) -> None:
        database = Path(self.temporary.name) / "delete-restart.sqlite3"
        root = Path(self.temporary.name) / "delete-restart-derived"
        connection = sqlite3.connect(database)
        initialize_schema(connection)
        store = EvidenceStore(connection, root)
        values = dict(self.binding)
        values.pop("manifest_digest")
        store.put_manifest(manifest=self.manifest, **values)
        store.put_preview(
            evidence_id="evidence_keyframe",
            preview_revision_id="preview_restart_delete",
            content_type="image/png",
            size_bytes=len(PNG),
            content_digest=sha256_digest(PNG),
            body=PNG,
            **self.binding,
        )

        def crash_before_file_cleanup(operation_id=None):
            raise SimulatedProcessCrash()

        store._drain_file_journal = crash_before_file_cleanup
        with self.assertRaises(SimulatedProcessCrash):
            store.delete_session(
                organization_id=ORG, project_id=PROJECT, session_id=SESSION
            )
        connection.close()

        recovered_connection = sqlite3.connect(database)
        try:
            recovered = EvidenceStore(recovered_connection, root)
            report = recovered.recover_file_journal()
            self.assertEqual(1, report["preview_files_removed"])
            self.assertEqual(1, report["directory_journal_entries"])
            self.assertEqual(1, report["session_trees_pruned"])
            self.assertFalse((root / "sessions" / SESSION).exists())
            for table in (
                "tacua_evidence_file_journal",
                "tacua_evidence_directory_journal",
            ):
                self.assertEqual(
                    0,
                    recovered_connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0],
                )
        finally:
            recovered_connection.close()

    def test_session_deletion_recovers_after_file_cleanup_before_tree_prune(self) -> None:
        self.put_manifest()
        self.put_preview()
        original_drain = self.store._drain_directory_journal

        def crash_before_tree_prune(operation_id=None):
            raise SimulatedProcessCrash()

        self.store._drain_directory_journal = crash_before_tree_prune
        with self.assertRaises(SimulatedProcessCrash):
            self.store.delete_session(
                organization_id=ORG, project_id=PROJECT, session_id=SESSION
            )
        self.assertEqual(
            0,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_file_journal"
            ).fetchone()[0],
        )
        self.assertEqual(
            1,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_directory_journal"
            ).fetchone()[0],
        )
        self.assertTrue((self.root / "sessions" / SESSION).is_dir())

        self.store._drain_directory_journal = original_drain
        report = self.store.recover_file_journal()
        self.assertEqual(1, report["directory_journal_entries"])
        self.assertEqual(1, report["session_trees_pruned"])
        self.assertFalse((self.root / "sessions" / SESSION).exists())

    def test_session_deletion_recovers_after_tree_prune_before_journal_clear(self) -> None:
        self.put_manifest()
        self.put_preview()
        original_clear = self.store._clear_directory_journal_row

        def crash_before_tree_journal_clear(journal_row_id):
            raise SimulatedProcessCrash()

        self.store._clear_directory_journal_row = crash_before_tree_journal_clear
        with self.assertRaises(SimulatedProcessCrash):
            self.store.delete_session(
                organization_id=ORG, project_id=PROJECT, session_id=SESSION
            )
        self.assertFalse((self.root / "sessions" / SESSION).exists())
        self.assertEqual(
            1,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_directory_journal"
            ).fetchone()[0],
        )

        self.store._clear_directory_journal_row = original_clear
        report = self.store.recover_file_journal()
        self.assertEqual(1, report["directory_journal_entries"])
        self.assertEqual(0, report["session_trees_pruned"])
        self.assertEqual(
            0,
            self.connection.execute(
                "SELECT COUNT(*) FROM tacua_evidence_directory_journal"
            ).fetchone()[0],
        )

    def test_filesystem_operations_reject_caller_rollback_boundaries(self) -> None:
        self.put_manifest()
        self.put_preview()
        self.connection.execute("BEGIN")
        try:
            self.assert_error(
                "EVIDENCE_TRANSACTION_ACTIVE",
                lambda: self.store.mark_preview_unavailable(
                    evidence_id="evidence_keyframe",
                    preview_revision_id="preview_expired",
                    reason="outside_retention",
                    detail="Retention expired.",
                    **self.binding,
                ),
            )
            self.assert_error(
                "EVIDENCE_TRANSACTION_ACTIVE",
                lambda: self.store.delete_session(
                    organization_id=ORG,
                    project_id=PROJECT,
                    session_id=SESSION,
                ),
            )
        finally:
            self.connection.rollback()
        self.assertEqual(
            PNG,
            self.store.get_preview(
                evidence_id="evidence_keyframe", **self.binding
            )["body"],
        )

    def test_audit_schema_and_rows_are_content_free(self) -> None:
        self.put_manifest()
        self.put_preview()
        columns = {
            row[1]
            for row in self.connection.execute(
                "PRAGMA table_info(tacua_evidence_audit)"
            ).fetchall()
        }
        for forbidden in (
            "body",
            "content",
            "description",
            "relative_path",
            "unavailable_detail",
            "secret",
        ):
            self.assertNotIn(forbidden, columns)
        rows = self.connection.execute(
            "SELECT * FROM tacua_evidence_audit"
        ).fetchall()
        encoded = json.dumps(rows)
        self.assertNotIn("SENTINEL-DESCRIPTION", encoded)
        self.assertNotIn(base64.b64encode(PNG).decode("ascii"), encoded)

    def test_non_keyframe_preview_and_tampered_db_path_fail_closed(self) -> None:
        self.put_manifest()
        self.assert_error(
            "PREVIEW_EVIDENCE_TYPE_INVALID",
            lambda: self.put_preview(evidence_id="evidence_route"),
        )
        self.put_preview()
        self.connection.execute(
            "UPDATE tacua_evidence_preview_revisions SET relative_path = '../../escape'"
        )
        self.assert_error(
            "PREVIEW_PATH_ESCAPE",
            lambda: self.store.get_preview(
                evidence_id="evidence_keyframe", **self.binding
            ),
        )

    def test_schema_initialization_is_explicit(self) -> None:
        connection = sqlite3.connect(":memory:")
        try:
            store = EvidenceStore(
                connection, Path(self.temporary.name) / "without-schema"
            )
            self.assert_error(
                "EVIDENCE_SCHEMA_MISSING",
                lambda: store.get_manifest(**self.binding),
            )
        finally:
            connection.close()

    def test_caller_row_factory_is_supported_without_being_mutated(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        try:
            initialize_schema(connection)
            store = EvidenceStore(
                connection, Path(self.temporary.name) / "row-factory"
            )
            values = dict(self.binding)
            values.pop("manifest_digest")
            store.put_manifest(manifest=self.manifest, **values)
            self.assertEqual(
                self.manifest["manifest_digest"],
                store.get_manifest(**self.binding)["manifest_digest"],
            )
            self.assertIs(connection.row_factory, sqlite3.Row)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
