# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE = REPOSITORY_ROOT / "services" / "backend" / "src"
CANDIDATE_FIXTURE = (
    REPOSITORY_ROOT
    / "contracts"
    / "ticket-candidate"
    / "fixtures"
    / "positive"
    / "version-4-approved.json"
)
SDK_BUILD_FIXTURE = (
    REPOSITORY_ROOT
    / "contracts"
    / "sdk-backend-protocol"
    / "fixtures"
    / "positive"
    / "build-identity.json"
)
sys.path.insert(0, str(SOURCE))

from tacua_backend.candidate_domain import TICKET_CONTRACT  # noqa: E402
from tacua_backend.evidence_domain import (  # noqa: E402
    ITEM_VERSION,
    MANIFEST_MEDIA_TYPE,
    MANIFEST_VERSION,
    seal_item,
    seal_manifest,
    sha256_digest,
)
from tacua_backend.handoff_export import (  # noqa: E402
    HANDOFF,
    HandoffArtifacts,
    export_approved_candidate,
)
from tacua_backend.handoff_store import (  # noqa: E402
    HandoffStore,
    HandoffStoreError,
    initialize_schema,
)


PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "YAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)
AUTHORITY = {
    "purpose": "implement_approved_ticket",
    "allowed_repositories": ["repo_mobile"],
    "read_authorized_evidence": True,
    "modify_code": True,
    "run_tests": True,
    "external_writes": False,
    "merge": False,
    "deploy": False,
}


def evidence_item(candidate: dict, evidence_id: str, index: int) -> dict:
    item_types = {
        "evidence_keyframe_001": ("media.keyframe", "mobile_sdk", "image/png"),
        "evidence_repository_001": (
            "repository.commit_snapshot",
            "repository",
            "application/vnd.tacua.connector-snapshot+json",
        ),
        "evidence_route_001": (
            "sdk.route_transition",
            "mobile_sdk",
            "application/vnd.tacua.sdk-event+json",
        ),
        "evidence_transcript_001": (
            "media.transcript_excerpt",
            "mobile_sdk",
            "text/plain",
        ),
    }
    evidence_type, component, content_type = item_types[evidence_id]
    payload = PNG if evidence_type == "media.keyframe" else f"payload:{evidence_id}".encode()
    sdk_build = json.loads(SDK_BUILD_FIXTURE.read_text(encoding="utf-8"))
    return seal_item(
        {
            "contract_version": ITEM_VERSION,
            "organization_id": candidate["organization_id"],
            "project_id": candidate["project_id"],
            "session_id": candidate["session_id"],
            "evidence_id": evidence_id,
            "evidence_type": evidence_type,
            "availability": "available",
            "description": f"Synthetic exact evidence for {evidence_id}.",
            "time_range": {
                "start_ms": index * 100,
                "end_ms": index * 100 + 20,
                "clock": "session_monotonic",
            },
            "source": {
                "component": component,
                "source_id": "repo_mobile" if component == "repository" else "sdk_session",
                "snapshot_revision": (
                    sdk_build["source"]["git_revision"]
                    if component == "repository"
                    else f"snapshot_{index}"
                ),
                "captured_at": "2026-07-21T10:00:01Z",
            },
            "reference": {
                "locator": {
                    "scheme": "tacua-evidence",
                    "organization_id": candidate["organization_id"],
                    "project_id": candidate["project_id"],
                    "evidence_id": evidence_id,
                    "revision_id": f"revision_{index}",
                },
                "content_type": content_type,
                "size_bytes": len(payload),
                "content_digest": sha256_digest(payload),
            },
            "unavailable": None,
            "evidence_item_digest": "sha256:" + "0" * 64,
        }
    )


def approved_candidate_and_manifest() -> tuple[dict, dict, dict]:
    sdk_build = json.loads(SDK_BUILD_FIXTURE.read_text(encoding="utf-8"))
    candidate = TICKET_CONTRACT.load_json(CANDIDATE_FIXTURE)
    candidate["build_id"] = sdk_build["build_id"]
    candidate["build_identity_digest"] = sdk_build["build_identity_digest"]
    evidence_ids = list(candidate["approval"]["authorized_evidence_ids"])
    manifest = seal_manifest(
        {
            "contract_version": MANIFEST_VERSION,
            "media_type": MANIFEST_MEDIA_TYPE,
            "organization_id": candidate["organization_id"],
            "project_id": candidate["project_id"],
            "session_id": candidate["session_id"],
            "manifest_id": "manifest_handoff_store",
            "items": [
                evidence_item(candidate, evidence_id, index)
                for index, evidence_id in enumerate(evidence_ids, start=1)
            ],
            "manifest_digest": "sha256:" + "0" * 64,
        }
    )
    candidate["evidence_manifest"] = {
        "manifest_id": manifest["manifest_id"],
        "manifest_digest": manifest["manifest_digest"],
        "evidence_ids": evidence_ids,
    }
    candidate = TICKET_CONTRACT.seal(candidate)
    TICKET_CONTRACT.validate(candidate)
    return candidate, manifest, sdk_build


def handoff_build_identity(candidate: dict, sdk_build: dict) -> dict:
    return HANDOFF.seal_build_identity(
        {
            "contract_version": "tacua.build-identity@1.0.0",
            "media_type": "application/vnd.tacua.build-identity+json;version=1.0.0",
            "organization_id": candidate["organization_id"],
            "project_id": candidate["project_id"],
            "build_id": sdk_build["build_id"],
            "mobile": {
                "platform": sdk_build["platform"],
                "application_id": sdk_build["bundle_identifier"],
                "app_version": sdk_build["native_version"],
                "build_number": sdk_build["native_build"],
                "distribution": "testflight",
                "source": {
                    "repository_id": "repo_mobile",
                    "revision": sdk_build["source"]["git_revision"],
                    "dirty": False,
                },
                "native_binary_digest": "sha256:" + "b" * 64,
            },
            "backend": {
                "availability": "unavailable",
                "environment": "self_hosted_qa",
                "deployment_id": None,
                "image_digest": None,
                "deployed_at": None,
                "sources": [],
                "unavailable_reason": "deployment_identity_unavailable",
            },
            "sdk": {
                "package_name": "@tacua/mobile-sdk",
                "package_version": "0.1.0",
                "source_revision": "c" * 40,
                "capture_schema_version": "tacua.sdk-evidence@1.0.0",
                "configuration_digest": sdk_build["transport_configuration_digest"],
            },
            "build_identity_digest": "sha256:" + "0" * 64,
        }
    )


def exported(
    candidate: dict,
    manifest: dict,
    sdk_build: dict,
    *,
    supersedes: str | None = None,
    registry_revision: str = "registry_local_001",
) -> HandoffArtifacts:
    return export_approved_candidate(
        candidate=candidate,
        evidence_manifest=manifest,
        sdk_build_identity=sdk_build,
        handoff_build_identity=handoff_build_identity(candidate, sdk_build),
        authority=AUTHORITY,
        registry_revision=registry_revision,
        checked_at=datetime(2026, 7, 21, 10, 5, tzinfo=timezone.utc),
        supersedes_handoff_digest=supersedes,
    )


def candidate_variant(
    source: dict,
    *,
    candidate_id: str | None = None,
    version: int | None = None,
    approval_id: str | None = None,
) -> dict:
    candidate = copy.deepcopy(source)
    if candidate_id is not None:
        candidate["candidate_id"] = candidate_id
        for parent in candidate["lineage"]["parents"]:
            parent["candidate_id"] = candidate_id
    if version is not None:
        predecessor_digest = "sha256:" + f"{version % 10}" * 64
        candidate["candidate_version"] = version
        candidate["previous_candidate_digest"] = predecessor_digest
        candidate["lineage"]["parents"][0]["candidate_version"] = version - 1
        candidate["lineage"]["parents"][0]["candidate_digest"] = predecessor_digest
        candidate["approval"]["reviewed_candidate_version"] = version - 1
        candidate["approval"]["reviewed_candidate_digest"] = predecessor_digest
    if approval_id is not None:
        candidate["approval"]["approval_id"] = approval_id
    candidate = TICKET_CONTRACT.seal(candidate)
    TICKET_CONTRACT.validate(candidate)
    return candidate


class HandoffStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.addCleanup(self.connection.close)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute(
            """CREATE TABLE candidate_versions (
                   candidate_id TEXT NOT NULL,
                   candidate_version INTEGER NOT NULL,
                   candidate_digest TEXT NOT NULL,
                   canonical_json TEXT NOT NULL,
                   PRIMARY KEY (candidate_id, candidate_version)
               )"""
        )
        initialize_schema(self.connection)
        self.candidate, self.manifest, self.sdk_build = approved_candidate_and_manifest()
        self.artifacts = exported(self.candidate, self.manifest, self.sdk_build)
        self.store = HandoffStore(
            self.connection,
            organization_id=self.candidate["organization_id"],
            project_id=self.candidate["project_id"],
        )

    def assert_store_error(self, code: str, callback) -> HandoffStoreError:
        with self.assertRaises(HandoffStoreError) as caught:
            callback()
        self.assertEqual(code, caught.exception.code)
        return caught.exception

    def begin(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")

    def insert_candidate(self, candidate: dict) -> None:
        self.connection.execute(
            """INSERT INTO candidate_versions
                   (candidate_id, candidate_version, candidate_digest, canonical_json)
               VALUES (?, ?, ?, ?)""",
            (
                candidate["candidate_id"],
                candidate["candidate_version"],
                candidate["candidate_digest"],
                TICKET_CONTRACT.canonical_json(candidate),
            ),
        )

    def put(self, candidate: dict, artifacts_value: HandoffArtifacts):
        stored = self.store.put(candidate, artifacts_value)
        self.insert_candidate(candidate)
        return stored

    def test_put_requires_transaction_and_round_trips_exact_bytes(self) -> None:
        self.assert_store_error(
            "HANDOFF_TRANSACTION_REQUIRED",
            lambda: self.store.put(self.candidate, self.artifacts),
        )
        with self.connection:
            self.begin()
            created = self.put(self.candidate, self.artifacts)
            retry = self.store.put(copy.deepcopy(self.candidate), self.artifacts)

        self.assertEqual(self.artifacts.json_bytes, created.json_bytes)
        self.assertEqual(self.artifacts.markdown_bytes, created.markdown_bytes)
        self.assertEqual(
            TICKET_CONTRACT.canonical_json(self.candidate),
            self.artifacts.handoff["source_candidate"]["canonical_json"],
        )
        self.assertEqual(
            self.candidate["candidate_digest"],
            self.artifacts.handoff["source_candidate"]["candidate_digest"],
        )
        self.assertFalse(
            self.artifacts.handoff["source_candidate"]["canonical_json"].endswith(
                "\n"
            )
        )
        self.assertEqual(created, retry)
        self.assertTrue(created.current)
        self.assertEqual(created, self.store.get(self.candidate["candidate_id"]))
        self.assertEqual(
            created,
            self.store.get(
                self.candidate["candidate_id"], self.candidate["candidate_version"]
            ),
        )

    def test_candidate_transaction_rollback_removes_handoff(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "candidate write failed"):
            with self.connection:
                self.begin()
                self.put(self.candidate, self.artifacts)
                raise RuntimeError("candidate write failed")

        self.assert_store_error(
            "HANDOFF_NOT_FOUND",
            lambda: self.store.get(self.candidate["candidate_id"]),
        )

    def test_invalid_or_mismatched_candidate_fails_closed(self) -> None:
        invalid = copy.deepcopy(self.candidate)
        invalid["content"]["title"] = "Unsealed title"
        with self.connection:
            self.begin()
            self.assert_store_error(
                "HANDOFF_CANDIDATE_INVALID",
                lambda: self.store.put(invalid, self.artifacts),
            )

        mismatched = candidate_variant(
            self.candidate,
            candidate_id="candidate_other_ticket",
            approval_id="approval_other_ticket",
        )
        with self.connection:
            self.begin()
            self.assert_store_error(
                "HANDOFF_CANDIDATE_MISMATCH",
                lambda: self.store.put(mismatched, self.artifacts),
            )

    def test_unprojected_source_change_cannot_be_substituted(self) -> None:
        altered = copy.deepcopy(self.candidate)
        altered["transition"]["reason"] = (
            "A different exact source snapshot with the same ticket projection."
        )
        altered = TICKET_CONTRACT.seal(altered)
        TICKET_CONTRACT.validate(altered)
        altered_artifacts = exported(altered, self.manifest, self.sdk_build)
        self.assertEqual(
            self.artifacts.handoff["ticket"]["title"],
            altered_artifacts.handoff["ticket"]["title"],
        )
        self.assertNotEqual(
            self.artifacts.handoff["source_candidate"]["candidate_digest"],
            altered_artifacts.handoff["source_candidate"]["candidate_digest"],
        )
        with self.connection:
            self.begin()
            self.assert_store_error(
                "HANDOFF_CANDIDATE_MISMATCH",
                lambda: self.store.put(self.candidate, altered_artifacts),
            )

        with self.connection:
            self.begin()
            self.put(self.candidate, self.artifacts)
        with self.connection:
            self.begin()
            self.connection.execute(
                """UPDATE candidate_versions
                      SET candidate_digest = ?, canonical_json = ?
                    WHERE candidate_id = ? AND candidate_version = ?""",
                (
                    altered["candidate_digest"],
                    TICKET_CONTRACT.canonical_json(altered),
                    altered["candidate_id"],
                    altered["candidate_version"],
                ),
            )
        self.assert_store_error(
            "HANDOFF_STORAGE_CORRUPT",
            lambda: self.store.get(self.candidate["candidate_id"]),
        )

    def test_exact_version_is_immutable_and_corruption_fails_closed(self) -> None:
        with self.connection:
            self.begin()
            self.put(self.candidate, self.artifacts)

        changed_artifacts = exported(
            self.candidate,
            self.manifest,
            self.sdk_build,
            registry_revision="registry_local_changed",
        )
        with self.connection:
            self.begin()
            self.assert_store_error(
                "HANDOFF_VERSION_COLLISION",
                lambda: self.store.put(self.candidate, changed_artifacts),
            )

        with self.connection:
            self.begin()
            self.connection.execute(
                "UPDATE approved_handoffs SET registry_revision = ?",
                ("registry_tampered",),
            )
        self.assert_store_error(
            "HANDOFF_STORAGE_CORRUPT",
            lambda: self.store.get(self.candidate["candidate_id"]),
        )

    def test_supersession_is_explicit_monotonic_and_only_latest_is_current(self) -> None:
        with self.connection:
            self.begin()
            first = self.put(self.candidate, self.artifacts)

        older = candidate_variant(
            self.candidate,
            version=self.candidate["candidate_version"] - 1,
            approval_id="approval_older",
        )
        older_artifacts = exported(
            older,
            self.manifest,
            self.sdk_build,
            supersedes=first.handoff_digest,
            registry_revision="registry_local_older",
        )
        with self.connection:
            self.begin()
            self.assert_store_error(
                "HANDOFF_SUPERSESSION_MISMATCH",
                lambda: self.store.put(older, older_artifacts),
            )

        second_candidate = candidate_variant(
            self.candidate,
            version=self.candidate["candidate_version"] + 1,
            approval_id="approval_newer",
        )
        second_artifacts = exported(
            second_candidate,
            self.manifest,
            self.sdk_build,
            supersedes=first.handoff_digest,
            registry_revision="registry_local_002",
        )
        with self.connection:
            self.begin()
            second = self.put(second_candidate, second_artifacts)

        self.assertEqual(second, self.store.get(self.candidate["candidate_id"]))
        self.assertFalse(
            self.store.get(
                self.candidate["candidate_id"], self.candidate["candidate_version"]
            ).current
        )
        self.assertTrue(second.current)

    def test_failed_supersession_preserves_current_handoff(self) -> None:
        with self.connection:
            self.begin()
            first = self.put(self.candidate, self.artifacts)

        second_candidate = candidate_variant(
            self.candidate,
            version=self.candidate["candidate_version"] + 1,
            approval_id="approval_newer",
        )
        second_artifacts = exported(
            second_candidate,
            self.manifest,
            self.sdk_build,
            supersedes=first.handoff_digest,
            registry_revision="registry_local_002",
        )
        self.connection.execute(
            """CREATE TRIGGER reject_new_handoff
               BEFORE INSERT ON approved_handoffs
               WHEN NEW.candidate_version = 5
               BEGIN SELECT RAISE(ABORT, 'synthetic conflict'); END"""
        )
        with self.connection:
            self.begin()
            self.assert_store_error(
                "HANDOFF_STORAGE_CONFLICT",
                lambda: self.store.put(second_candidate, second_artifacts),
            )

        still_current = self.store.get(self.candidate["candidate_id"])
        self.assertEqual(first.handoff_digest, still_current.handoff_digest)
        self.assertTrue(still_current.current)

    def test_reads_are_scoped_and_session_delete_is_transactional(self) -> None:
        with self.connection:
            self.begin()
            self.put(self.candidate, self.artifacts)
        foreign = HandoffStore(
            self.connection,
            organization_id="org_foreign",
            project_id="project_foreign",
        )
        self.assert_store_error(
            "HANDOFF_NOT_FOUND",
            lambda: foreign.get(self.candidate["candidate_id"]),
        )

        with self.assertRaisesRegex(RuntimeError, "deletion failed"):
            with self.connection:
                self.begin()
                self.assertEqual(
                    1, self.store.delete_session(self.candidate["session_id"])
                )
                raise RuntimeError("deletion failed")
        self.assertEqual(
            self.candidate["candidate_id"],
            self.store.get(self.candidate["candidate_id"]).candidate_id,
        )

        with self.connection:
            self.begin()
            self.assertEqual(0, self.store.delete_session("session_other"))
            self.assertEqual(1, self.store.delete_session(self.candidate["session_id"]))
        self.assert_store_error(
            "HANDOFF_NOT_FOUND",
            lambda: self.store.get(self.candidate["candidate_id"]),
        )


if __name__ == "__main__":
    unittest.main()
