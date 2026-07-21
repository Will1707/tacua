# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import base64
from contextlib import closing
from datetime import datetime, timedelta, timezone
from email.message import Message
import io
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "src"
REPOSITORY = SOURCE.parents[2]
FIXTURES = REPOSITORY / "contracts" / "sdk-backend-protocol" / "fixtures" / "positive"
sys.path.insert(0, str(SOURCE))

from tacua_backend.config import (  # noqa: E402
    ConfigError,
    PilotConfig,
    load_config,
    normalize_backend_origin,
)
from tacua_backend.candidate_domain import TICKET_CONTRACT  # noqa: E402
from tacua_backend.contracts import (  # noqa: E402
    PROTOCOL_VERSION,
    canonical_json,
    digest,
    runtime_seal,
    seal,
    validate,
    validate_operation_pair,
)
from tacua_backend.http_api import PilotRequestHandler, create_server  # noqa: E402
from tacua_backend.handoff_export import (  # noqa: E402
    HANDOFF,
    HandoffExportError,
    export_approved_candidate,
)
from tacua_backend.evidence_domain import (  # noqa: E402
    EvidenceStore,
    ITEM_VERSION,
    MANIFEST_MEDIA_TYPE,
    MANIFEST_VERSION,
    seal_item,
    seal_manifest,
    sha256_digest,
)
from tacua_backend.service import (  # noqa: E402
    ApiError,
    InvalidJSONValue,
    MAX_CANDIDATE_EVIDENCE_VIEW_BYTES,
    PilotBackend,
    strict_json_loads,
)


def instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


class FakeClock:
    def __init__(self, value: str):
        self.value = instant(value)
        self.lock = threading.Lock()

    def __call__(self) -> datetime:
        with self.lock:
            return self.value

    def set(self, value: str | datetime) -> None:
        with self.lock:
            self.value = instant(value) if isinstance(value, str) else value


class ControlledRetentionWait:
    def __init__(self) -> None:
        self.wake = threading.Event()
        self.waiting = threading.Event()
        self.intervals: list[float] = []

    def __call__(self, stop_event: threading.Event, seconds: float) -> bool:
        self.intervals.append(seconds)
        self.waiting.set()
        while not stop_event.is_set():
            if self.wake.wait(0.01):
                self.wake.clear()
                self.waiting.clear()
                return False
        return True


class BackendHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.clock = FakeClock("2026-07-21T09:57:01Z")
        self.admin_secret = secrets.token_urlsafe(48).encode("ascii")
        build = fixture("build-identity")
        self.build = build
        self.scope = fixture("capture-scope")
        self.config = PilotConfig(
            organization_id=self.scope["organization_id"],
            project_id=self.scope["project_id"],
            application_id=self.scope["application_id"],
            build_identity=copy.deepcopy(build),
            consent_contract=self.scope["consent"]["policy_version"],
            backend_origin="https://qa.tacua.example",
            state_directory=Path(self.temporary.name),
            max_segment_bytes=1_048_576,
            max_diagnostic_bytes=1_048_576,
            max_completion_bytes=4_194_304,
        )
        self.backend = PilotBackend(self.config, self.admin_secret, clock=self.clock)

    def assert_api_error(self, status: int, code: str, callback) -> ApiError:
        with self.assertRaises(ApiError) as captured:
            callback()
        self.assertEqual(status, captured.exception.status)
        self.assertEqual(code, captured.exception.code)
        return captured.exception

    def start_session(
        self,
        *,
        credential_id: str = "credential_synthetic",
        secret: str = "S" * 43,
        exchange_id: str = "exchange_synthetic",
    ) -> tuple[dict, dict, bytes, dict]:
        grant = self.backend.create_launch_code(
            {
                "exchange_kind": "start_session",
                "build_id": self.build["build_id"],
            }
        )
        request = fixture("launch-exchange-request")
        consent_at = self.clock().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.scope["consent"]["granted_at"] = consent_at
        self.scope = seal(self.scope)
        request["exchange_id"] = exchange_id
        request["launch_code"] = grant["launch_code"]
        request["scope"] = copy.deepcopy(self.scope)
        request["requested_at"] = consent_at
        request["credential"]["credential_id"] = credential_id
        request["credential"]["secret"] = secret
        request = seal(request)
        response = self.backend.exchange_launch_code(request)
        self.assertEqual(201, response.status)
        receipt = response.json()
        validate_operation_pair(request, receipt)
        return request, receipt, response.body, grant

    def resume_session(
        self,
        session_id: str,
        previous_credential_id: str,
        *,
        state: str,
        completion_id: str | None,
        credential_id: str,
        secret: str,
        exchange_id: str,
        requested_at: str,
        accepted_at: str,
    ) -> tuple[dict, dict, bytes]:
        self.clock.set(requested_at)
        grant = self.backend.create_launch_code(
            {"exchange_kind": "resume_session", "session_id": session_id}
        )
        request = fixture(
            "receiving-resume-request" if state == "receiving" else "completed-resume-request"
        )
        request.update(
            {
                "exchange_id": exchange_id,
                "launch_code": grant["launch_code"],
                "expected_session_id": session_id,
                "expected_session_state": state,
                "expected_completion_id": completion_id,
                "previous_credential_id": previous_credential_id,
                "build_identity": copy.deepcopy(self.build),
                "scope": copy.deepcopy(self.scope),
                "requested_at": requested_at,
            }
        )
        request["credential"] = {
            "credential_id": credential_id,
            "secret": secret,
            "authentication_scheme": "Bearer",
            "local_storage": "ios_keychain_when_unlocked_this_device_only",
        }
        request = seal(request)
        self.clock.set(accepted_at)
        response = self.backend.exchange_launch_code(request)
        receipt = response.json()
        validate_operation_pair(request, receipt)
        return request, receipt, response.body

    def store_segment(
        self,
        session_id: str,
        credential_id: str,
        secret: str,
        *,
        upload_id: str = "upload_segment_synthetic",
        sequence: int = 0,
        segment_id: str = "segment_synthetic",
        content: bytes = b"synthetic movie bytes",
        sidecar_digest: str = "sha256:" + "4" * 64,
        requested_at: str = "2026-07-21T10:01:59Z",
        accepted_at: str = "2026-07-21T10:02:00Z",
    ) -> tuple[dict, dict, bytes]:
        request = fixture("segment-upload-intent")
        request.update(
            {
                "upload_id": upload_id,
                "session_id": session_id,
                "scope_digest": self.scope["scope_digest"],
                "credential_id": credential_id,
                "sequence": sequence,
                "segment_id": segment_id,
                "sidecar_digest": sidecar_digest,
                "requested_at": requested_at,
                "transport": {
                    "content_type": "video/quicktime",
                    "size_bytes": len(content),
                    "content_digest": digest(content),
                },
            }
        )
        request = seal(request)
        self.clock.set(accepted_at)
        response = self.backend.upload_segment(
            session_id, sequence, segment_id, secret, request, io.BytesIO(content)
        )
        receipt = response.json()
        validate_operation_pair(request, receipt)
        return request, receipt, response.body

    def store_diagnostic(
        self,
        session_id: str,
        credential_id: str,
        secret: str,
        *,
        upload_id: str = "upload_diagnostic_synthetic",
        envelope_id: str = "envelope_synthetic",
    ) -> tuple[dict, dict, bytes]:
        request = fixture("diagnostic-upload-request")
        envelope = request["envelope"]
        envelope["session_id"] = session_id
        envelope["envelope_id"] = envelope_id
        envelope = runtime_seal(envelope)
        envelope_bytes = canonical_json(envelope).encode("utf-8")
        request.update(
            {
                "upload_id": upload_id,
                "session_id": session_id,
                "scope_digest": self.scope["scope_digest"],
                "credential_id": credential_id,
                "envelope": envelope,
                "transport": {
                    "content_type": "application/vnd.tacua.diagnostic-envelope+json;version=1.0.0",
                    "size_bytes": len(envelope_bytes),
                    "content_digest": digest(envelope_bytes),
                },
            }
        )
        request = seal(request)
        self.clock.set("2026-07-21T10:02:04Z")
        response = self.backend.upload_diagnostic(session_id, upload_id, secret, request)
        receipt = response.json()
        validate_operation_pair(request, receipt)
        return request, receipt, response.body

    def completion_request(
        self,
        session_id: str,
        credential_id: str,
        segment_receipts: list[dict],
        diagnostic_receipts: list[dict],
    ) -> dict:
        template = fixture("completion-request")
        manifest = template["capture_manifest"]
        manifest["session_id"] = session_id
        manifest["upload"]["remote_session_id"] = session_id
        manifest["segments"] = []
        manifest["upload"]["receipts"] = []
        for index, receipt in enumerate(segment_receipts):
            runtime_receipt = copy.deepcopy(receipt["runtime_receipt"])
            manifest["segments"].append(
                {
                    "segment_id": receipt["segment_id"],
                    "sequence": receipt["sequence"],
                    "time_range": {
                        "start_ms": index * 1000,
                        "end_ms": (index + 1) * 1000,
                        "clock": "session_monotonic",
                    },
                    "finalized": True,
                    "availability": "available",
                    "content": {
                        "content_type": receipt["content_type"],
                        "size_bytes": runtime_receipt["size_bytes"],
                        "content_digest": runtime_receipt["content_digest"],
                        "sidecar_digest": receipt["sidecar_digest"],
                    },
                    "unavailable": None,
                }
            )
            manifest["upload"]["receipts"].append(runtime_receipt)
        # Keep the frozen fixture's one-minute capture/gap chronology while
        # replacing only its available segment set.
        manifest["monotonic_duration_ms"] = 60_000
        manifest["upload"]["completed_at"] = "2026-07-21T10:02:00Z"
        session = self.backend.get_session(session_id)
        manifest["retention"]["raw_media_expires_at"] = session["retention"][
            "raw_media_expires_at"
        ]
        manifest["retention"]["derived_data_expires_at"] = session["retention"][
            "derived_data_expires_at"
        ]
        manifest = runtime_seal(manifest)
        request = {
            "protocol_version": PROTOCOL_VERSION,
            "message_type": "completion_request",
            "completion_id": "completion_synthetic",
            "session_id": session_id,
            "scope_digest": self.scope["scope_digest"],
            "credential_id": credential_id,
            "capture_manifest": manifest,
            "segment_receipts": copy.deepcopy(segment_receipts),
            "diagnostic_receipts": copy.deepcopy(diagnostic_receipts),
            "requested_at": "2026-07-21T10:02:05Z",
            "request_digest": "sha256:" + "0" * 64,
        }
        return seal(request)

    def complete(
        self,
        session_id: str,
        credential_id: str,
        secret: str,
        segment_receipts: list[dict],
        diagnostic_receipts: list[dict],
    ) -> tuple[dict, dict, bytes]:
        request = self.completion_request(
            session_id, credential_id, segment_receipts, diagnostic_receipts
        )
        self.clock.set("2026-07-21T10:02:06Z")
        response = self.backend.complete_session(
            session_id, request["completion_id"], secret, request
        )
        receipt = response.json()
        validate_operation_pair(request, receipt)
        return request, receipt, response.body

    def full_completed_session(self) -> dict:
        launch_request, launch_receipt, _, _ = self.start_session()
        segment_request, segment_receipt, segment_bytes = self.store_segment(
            launch_receipt["session_id"],
            launch_receipt["credential"]["credential_id"],
            launch_request["credential"]["secret"],
        )
        diagnostic_request, diagnostic_receipt, diagnostic_bytes = self.store_diagnostic(
            launch_receipt["session_id"],
            launch_receipt["credential"]["credential_id"],
            launch_request["credential"]["secret"],
        )
        completion_request, completion_receipt, completion_bytes = self.complete(
            launch_receipt["session_id"],
            launch_receipt["credential"]["credential_id"],
            launch_request["credential"]["secret"],
            [segment_receipt],
            [diagnostic_receipt],
        )
        return {
            "launch_request": launch_request,
            "launch_receipt": launch_receipt,
            "secret": launch_request["credential"]["secret"],
            "segment_request": segment_request,
            "segment_receipt": segment_receipt,
            "segment_bytes": segment_bytes,
            "diagnostic_request": diagnostic_request,
            "diagnostic_receipt": diagnostic_receipt,
            "diagnostic_bytes": diagnostic_bytes,
            "completion_request": completion_request,
            "completion_receipt": completion_receipt,
            "completion_bytes": completion_bytes,
        }

    @staticmethod
    def _replace_evidence_ids(value: object, replacements: dict[str, str]) -> object:
        if isinstance(value, str):
            return replacements.get(value, value)
        if isinstance(value, list):
            return [BackendHarness._replace_evidence_ids(item, replacements) for item in value]
        if isinstance(value, dict):
            return {
                key: BackendHarness._replace_evidence_ids(item, replacements)
                for key, item in value.items()
            }
        return value

    def candidate_bundle(self, session_id: str) -> tuple[dict, dict, list[dict]]:
        png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
            "YAAAAAYAAjCB0C8AAAAASUVORK5CYII="
        )
        identifiers = {
            "evidence_keyframe_001": "evidence_frame",
            "evidence_repository_001": "evidence_repository",
            "evidence_route_001": "evidence_route",
            "evidence_transcript_001": "evidence_transcript",
        }
        ticket_path = (
            REPOSITORY
            / "contracts"
            / "ticket-candidate"
            / "fixtures"
            / "positive"
            / "version-1-draft.json"
        )
        candidate = self._replace_evidence_ids(
            json.loads(ticket_path.read_text(encoding="utf-8")), identifiers
        )
        assert isinstance(candidate, dict)
        candidate.update(
            {
                "project_id": self.config.project_id,
                "session_id": session_id,
                "build_id": self.config.build_id,
                "build_identity_digest": self.config.build_identity_digest,
            }
        )

        specifications = (
            ("evidence_frame", "media.keyframe", "mobile_sdk", "image/png", 20_000),
            (
                "evidence_repository",
                "repository.commit_snapshot",
                "repository",
                "application/vnd.tacua.connector-snapshot+json",
                None,
            ),
            (
                "evidence_route",
                "sdk.route_transition",
                "mobile_sdk",
                "application/vnd.tacua.sdk-event+json",
                1_000,
            ),
            (
                "evidence_transcript",
                "media.transcript_excerpt",
                "mobile_sdk",
                "text/plain",
                19_000,
            ),
        )
        items = []
        for evidence_id, evidence_type, component, content_type, elapsed_ms in specifications:
            content = png if evidence_id == "evidence_frame" else evidence_id.encode("utf-8")
            item = {
                "contract_version": ITEM_VERSION,
                "organization_id": self.config.organization_id,
                "project_id": self.config.project_id,
                "session_id": session_id,
                "evidence_id": evidence_id,
                "evidence_type": evidence_type,
                "availability": "available",
                "description": f"Bound reviewer evidence for {evidence_id}.",
                "time_range": None
                if elapsed_ms is None
                else {
                    "start_ms": elapsed_ms,
                    "end_ms": elapsed_ms + 500,
                    "clock": "session_monotonic",
                },
                "source": {
                    "component": component,
                    "source_id": "repo_mobile" if component == "repository" else "sdk_session",
                    "snapshot_revision": self.build["source"]["git_revision"]
                    if component == "repository"
                    else f"snapshot_{evidence_id}",
                    "captured_at": "2026-07-21T10:00:20Z",
                },
                "reference": {
                    "locator": {
                        "scheme": "tacua-evidence",
                        "organization_id": self.config.organization_id,
                        "project_id": self.config.project_id,
                        "evidence_id": evidence_id,
                        "revision_id": f"revision_{evidence_id}",
                    },
                    "content_type": content_type,
                    "size_bytes": len(content),
                    "content_digest": sha256_digest(content),
                },
                "unavailable": None,
                "evidence_item_digest": "sha256:" + "0" * 64,
            }
            items.append(seal_item(item))
        manifest = seal_manifest(
            {
                "contract_version": MANIFEST_VERSION,
                "media_type": MANIFEST_MEDIA_TYPE,
                "organization_id": self.config.organization_id,
                "project_id": self.config.project_id,
                "session_id": session_id,
                "manifest_id": candidate["evidence_manifest"]["manifest_id"],
                "items": items,
                "manifest_digest": "sha256:" + "0" * 64,
            }
        )
        candidate["evidence_manifest"] = {
            "manifest_id": manifest["manifest_id"],
            "manifest_digest": manifest["manifest_digest"],
            "evidence_ids": [item["evidence_id"] for item in manifest["items"]],
        }
        candidate = TICKET_CONTRACT.seal(candidate)
        TICKET_CONTRACT.validate_chain([candidate])
        previews = [
            {
                "evidence_id": "evidence_frame",
                "preview_revision_id": "preview_primary",
                "content_type": "image/png",
                "size_bytes": len(png),
                "content_digest": sha256_digest(png),
                "body": png,
            }
        ]
        return candidate, manifest, previews

    def candidate_transition_body(
        self, parent: dict, action: str, **changes: object
    ) -> dict:
        body = {
            "expected_candidate_digest": parent["candidate_digest"],
            "candidate_version": parent["candidate_version"],
            "candidate_content_digest": parent["candidate_content_digest"],
            "evidence_manifest_digest": parent["evidence_manifest"]["manifest_digest"],
            "action": action,
            "actor_id": self.config.reviewer_id,
            "reason": f"reviewer_{action}",
        }
        if action == "resolve_clarification":
            body.update(
                {
                    "clarification_id": "clarification_copy_source",
                    "selected_choice_id": "choice_use_approved",
                }
            )
        body.update(changes)
        return body

    def handoff_build_identity(self) -> dict:
        return HANDOFF.seal_build_identity(
            {
                "contract_version": "tacua.build-identity@1.0.0",
                "media_type": "application/vnd.tacua.build-identity+json;version=1.0.0",
                "organization_id": self.config.organization_id,
                "project_id": self.config.project_id,
                "build_id": self.config.build_id,
                "mobile": {
                    "platform": self.build["platform"],
                    "application_id": self.build["bundle_identifier"],
                    "app_version": self.build["native_version"],
                    "build_number": self.build["native_build"],
                    "distribution": self.build["distribution"],
                    "source": {
                        "repository_id": "repo_mobile",
                        "revision": self.build["source"]["git_revision"],
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
                    "configuration_digest": self.build["transport_configuration_digest"],
                },
                "build_identity_digest": "sha256:" + "0" * 64,
            }
        )


class BackendProtocolTests(BackendHarness):

    def _assert_deletion_waits_for_blocked_review_read(
        self,
        session_id: str,
        reader,
        entered: threading.Event,
        release: threading.Event,
    ) -> list[object]:
        reader_results: list[object] = []
        reader_errors: list[BaseException] = []
        deletion_results: list[object] = []
        deletion_errors: list[BaseException] = []
        deletion_started = threading.Event()
        deletion_done = threading.Event()

        def run_reader() -> None:
            try:
                reader_results.append(reader())
            except BaseException as error:  # pragma: no cover - asserted below
                reader_errors.append(error)

        def run_deletion() -> None:
            deletion_started.set()
            try:
                deletion_results.append(self.backend.delete_session(session_id))
            except BaseException as error:  # pragma: no cover - asserted below
                deletion_errors.append(error)
            finally:
                deletion_done.set()

        read_thread = threading.Thread(target=run_reader)
        delete_thread = threading.Thread(target=run_deletion)
        read_thread.start()
        self.assertTrue(entered.wait(2), "review read did not reach its barrier")
        delete_thread.start()
        self.assertTrue(deletion_started.wait(1))
        deletion_was_blocked = not deletion_done.wait(0.25)
        with self.backend._connect() as connection:
            pending_while_reading = connection.execute(
                "SELECT COUNT(*) FROM pending_deletions WHERE session_id = ?",
                (session_id,),
            ).fetchone()[0]
        release.set()
        read_thread.join(5)
        delete_thread.join(5)

        self.assertTrue(deletion_was_blocked)
        self.assertEqual(0, pending_while_reading)
        self.assertFalse(read_thread.is_alive())
        self.assertFalse(delete_thread.is_alive())
        self.assertEqual([], reader_errors)
        self.assertEqual([], deletion_errors)
        self.assertEqual(1, len(deletion_results))
        self.assert_api_error(
            410,
            "SESSION_DELETED",
            lambda: self.backend.get_session(session_id),
        )
        return reader_results

    def test_candidate_publication_and_deletion_are_one_process_critical_section(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        entered = threading.Event()
        release = threading.Event()
        publication_results: list[dict] = []
        publication_errors: list[BaseException] = []
        deletion_results: list[dict] = []
        deletion_errors: list[BaseException] = []
        deletion_started = threading.Event()
        deletion_done = threading.Event()
        original_put_preview = EvidenceStore.put_preview

        def blocked_put_preview(store: EvidenceStore, **values: object) -> dict:
            entered.set()
            if not release.wait(5):
                raise AssertionError("publication barrier timed out")
            return original_put_preview(store, **values)

        def publish() -> None:
            try:
                publication_results.append(
                    self.backend.persist_candidate_bundle(
                        candidate=candidate,
                        evidence_manifest=manifest,
                        previews=previews,
                    )
                )
            except BaseException as error:  # pragma: no cover - asserted below
                publication_errors.append(error)

        def delete() -> None:
            deletion_started.set()
            try:
                deletion_results.append(self.backend.delete_session(session_id))
            except BaseException as error:  # pragma: no cover - asserted below
                deletion_errors.append(error)
            finally:
                deletion_done.set()

        with patch.object(EvidenceStore, "put_preview", new=blocked_put_preview):
            publisher = threading.Thread(target=publish)
            deleter = threading.Thread(target=delete)
            publisher.start()
            self.assertTrue(entered.wait(2), "publication did not reach its barrier")
            deleter.start()
            self.assertTrue(deletion_started.wait(1))
            deletion_was_blocked = not deletion_done.wait(0.25)
            with self.backend._connect() as connection:
                pending_while_publishing = connection.execute(
                    "SELECT COUNT(*) FROM pending_deletions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()[0]
            release.set()
            publisher.join(5)
            deleter.join(5)

        self.assertTrue(deletion_was_blocked)
        self.assertEqual(0, pending_while_publishing)
        self.assertFalse(publisher.is_alive())
        self.assertFalse(deleter.is_alive())
        self.assertEqual([], publication_errors)
        self.assertEqual([], deletion_errors)
        self.assertEqual([candidate], publication_results)
        self.assertEqual(1, len(deletion_results))
        with self.backend._connect() as connection:
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM candidate_versions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()[0],
            )

    def test_candidate_read_finishes_before_deletion_is_accepted(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.backend.persist_candidate_bundle(
            candidate=candidate, evidence_manifest=manifest, previews=previews
        )
        entered = threading.Event()
        release = threading.Event()
        original = self.backend._candidate_from_connection

        def blocked_candidate_read(
            connection: sqlite3.Connection,
            candidate_id: str,
            version: int | None = None,
        ) -> dict:
            value = original(connection, candidate_id, version)
            entered.set()
            if not release.wait(5):
                raise AssertionError("candidate read barrier timed out")
            return value

        with patch.object(
            self.backend,
            "_candidate_from_connection",
            side_effect=blocked_candidate_read,
        ):
            results = self._assert_deletion_waits_for_blocked_review_read(
                session_id,
                lambda: self.backend.get_candidate(candidate["candidate_id"]),
                entered,
                release,
            )
        self.assertEqual([candidate], results)

    def test_evidence_metadata_read_finishes_before_deletion_is_accepted(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.backend.persist_candidate_bundle(
            candidate=candidate, evidence_manifest=manifest, previews=previews
        )
        entered = threading.Event()
        release = threading.Event()
        original = EvidenceStore.get_candidate_evidence_view

        def blocked_evidence_read(store: EvidenceStore, **values: object) -> dict:
            value = original(store, **values)
            entered.set()
            if not release.wait(5):
                raise AssertionError("evidence metadata read barrier timed out")
            return value

        with patch.object(
            EvidenceStore,
            "get_candidate_evidence_view",
            new=blocked_evidence_read,
        ):
            results = self._assert_deletion_waits_for_blocked_review_read(
                session_id,
                lambda: self.backend.get_candidate_evidence(
                    candidate["candidate_id"],
                    candidate["candidate_version"],
                    candidate_digest=candidate["candidate_digest"],
                    manifest_digest=manifest["manifest_digest"],
                ),
                entered,
                release,
            )
        self.assertEqual(candidate["candidate_id"], results[0]["candidate_id"])

    def test_preview_bytes_finish_reading_before_deletion_is_accepted(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.backend.persist_candidate_bundle(
            candidate=candidate, evidence_manifest=manifest, previews=previews
        )
        entered = threading.Event()
        release = threading.Event()
        original = EvidenceStore.get_preview

        def blocked_preview_read(store: EvidenceStore, **values: object) -> dict:
            value = original(store, **values)
            entered.set()
            if not release.wait(5):
                raise AssertionError("preview read barrier timed out")
            return value

        with patch.object(EvidenceStore, "get_preview", new=blocked_preview_read):
            results = self._assert_deletion_waits_for_blocked_review_read(
                session_id,
                lambda: self.backend.get_candidate_preview(
                    candidate["candidate_id"],
                    candidate["candidate_version"],
                    "evidence_frame",
                    candidate_digest=candidate["candidate_digest"],
                    manifest_digest=manifest["manifest_digest"],
                ),
                entered,
                release,
            )
        self.assertEqual(previews[0]["body"], results[0]["body"])

    def test_candidate_evidence_view_uses_a_deterministic_bounded_event_prefix(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.backend.persist_candidate_bundle(
            candidate=candidate, evidence_manifest=manifest, previews=previews
        )
        events = [
            {
                "event_id": f"event_large_{index:04d}",
                "event_type": "runtime_error",
                "source": "mobile_sdk",
                "sequence": index,
                "elapsed_ms": index,
                "occurred_at": "2026-07-21T10:00:20Z",
                "evidence_refs": ["evidence_frame"],
                "data": {"detail": "x" * 6_000},
            }
            for index in range(400)
        ]
        with patch.object(
            self.backend,
            "_candidate_diagnostic_events",
            return_value=events,
        ):
            first = self.backend.get_candidate_evidence(
                candidate["candidate_id"],
                candidate["candidate_version"],
                candidate_digest=candidate["candidate_digest"],
                manifest_digest=manifest["manifest_digest"],
            )
            second = self.backend.get_candidate_evidence(
                candidate["candidate_id"],
                candidate["candidate_version"],
                candidate_digest=candidate["candidate_digest"],
                manifest_digest=manifest["manifest_digest"],
            )
        self.assertEqual(first, second)
        encoded = canonical_json(first).encode("utf-8")
        self.assertLessEqual(len(encoded), MAX_CANDIDATE_EVIDENCE_VIEW_BYTES)
        returned = first["diagnostic_events"]
        self.assertGreater(len(returned), 0)
        self.assertLess(len(returned), len(events))
        self.assertEqual(events[: len(returned)], returned)
        self.assertEqual(
            {
                "contract_version",
                "candidate_id",
                "candidate_version",
                "candidate_digest",
                "evidence_manifest_digest",
                "items",
                "diagnostic_events",
            },
            set(first),
        )

    def test_diagnostic_projection_revalidates_canonical_outer_request_and_object(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.backend.persist_candidate_bundle(
            candidate=candidate, evidence_manifest=manifest, previews=previews
        )
        with self.backend._connect() as connection:
            connection.execute(
                "UPDATE diagnostics SET request_json = ' ' || request_json WHERE session_id = ?",
                (session_id,),
            )
        self.assert_api_error(
            500,
            "DIAGNOSTIC_STORAGE_CORRUPT",
            lambda: self.backend.get_candidate_evidence(
                candidate["candidate_id"],
                candidate["candidate_version"],
                candidate_digest=candidate["candidate_digest"],
                manifest_digest=manifest["manifest_digest"],
            ),
        )

        with self.backend._connect() as connection:
            row = connection.execute(
                "SELECT relative_path FROM diagnostics WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            connection.execute(
                "UPDATE diagnostics SET request_json = ? WHERE session_id = ?",
                (canonical_json(lifecycle["diagnostic_request"]), session_id),
            )
        (self.backend.state_dir / row["relative_path"]).write_bytes(b"{}")
        self.assert_api_error(
            500,
            "STORAGE_INCONSISTENT",
            lambda: self.backend.get_candidate_evidence(
                candidate["candidate_id"],
                candidate["candidate_version"],
                candidate_digest=candidate["candidate_digest"],
                manifest_digest=manifest["manifest_digest"],
            ),
        )

    def test_diagnostic_projection_rejects_a_coherently_rewritten_build_scope(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.backend.persist_candidate_bundle(
            candidate=candidate, evidence_manifest=manifest, previews=previews
        )
        request = copy.deepcopy(lifecycle["diagnostic_request"])
        request["envelope"]["build_id"] = "build_rewritten"
        request["envelope"]["build_identity_digest"] = "sha256:" + "a" * 64
        request["envelope"] = runtime_seal(request["envelope"])
        envelope_bytes = canonical_json(request["envelope"]).encode("utf-8")
        request["transport"]["size_bytes"] = len(envelope_bytes)
        request["transport"]["content_digest"] = digest(envelope_bytes)
        request = seal(request)
        response = copy.deepcopy(lifecycle["diagnostic_receipt"])
        response["request_digest"] = request["request_digest"]
        response["size_bytes"] = len(envelope_bytes)
        response["transport_digest"] = digest(envelope_bytes)
        response["envelope_digest"] = request["envelope"]["envelope_digest"]
        response = seal(response)
        validate_operation_pair(request, response)
        with self.backend._connect() as connection:
            row = connection.execute(
                "SELECT relative_path FROM diagnostics WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            connection.execute(
                """UPDATE diagnostics
                      SET request_digest = ?, request_json = ?, response_bytes = ?,
                          size_bytes = ?, content_digest = ?
                    WHERE session_id = ?""",
                (
                    request["request_digest"],
                    canonical_json(request),
                    canonical_json(response).encode("utf-8"),
                    len(envelope_bytes),
                    digest(envelope_bytes),
                    session_id,
                ),
            )
        (self.backend.state_dir / row["relative_path"]).write_bytes(envelope_bytes)
        self.assert_api_error(
            500,
            "DIAGNOSTIC_STORAGE_CORRUPT",
            lambda: self.backend.get_candidate_evidence(
                candidate["candidate_id"],
                candidate["candidate_version"],
                candidate_digest=candidate["candidate_digest"],
                manifest_digest=manifest["manifest_digest"],
            ),
        )

    def test_missing_committed_preview_is_server_corruption_not_not_found(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.backend.persist_candidate_bundle(
            candidate=candidate, evidence_manifest=manifest, previews=previews
        )
        with self.backend._connect() as connection:
            relative_path = connection.execute(
                "SELECT relative_path FROM tacua_evidence_preview_revisions "
                "WHERE relative_path IS NOT NULL"
            ).fetchone()[0]
        (self.backend.derived_evidence_dir / relative_path).unlink()
        self.assert_api_error(
            500,
            "CANDIDATE_EVIDENCE_CORRUPT",
            lambda: self.backend.get_candidate_preview(
                candidate["candidate_id"],
                candidate["candidate_version"],
                "evidence_frame",
                candidate_digest=candidate["candidate_digest"],
                manifest_digest=manifest["manifest_digest"],
            ),
        )

    def test_erased_object_count_uses_top_level_artifacts_and_physical_previews(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.backend.persist_candidate_bundle(
            candidate=candidate, evidence_manifest=manifest, previews=previews
        )
        with self.backend._connect() as connection:
            row = connection.execute(
                """SELECT manifest_row_id,item_row_id
                     FROM tacua_evidence_preview_revisions
                    WHERE relative_path IS NOT NULL"""
            ).fetchone()
            connection.execute(
                """INSERT INTO tacua_evidence_preview_revisions
                   (manifest_row_id,item_row_id,preview_revision_id,availability,
                    content_type,size_bytes,content_digest,relative_path,
                    unavailable_reason,unavailable_detail,recorded_at)
                   VALUES (?,?,'preview_metadata_only','unavailable',
                           NULL,NULL,NULL,NULL,'outside_retention',
                           'Metadata-only unavailable revision.',
                           '2026-07-21T10:02:07Z')""",
                (row["manifest_row_id"], row["item_row_id"]),
            )
            connection.execute(
                """INSERT INTO tacua_evidence_audit
                   (occurred_at,action,organization_id,project_id,session_id)
                   VALUES ('2026-07-21T10:02:07Z','count_regression',?,?,?)""",
                (self.config.organization_id, self.config.project_id, session_id),
            )
        tombstone = self.backend.delete_session(session_id)
        # One segment, diagnostic envelope, completion artifact, processing
        # job, and physical preview. Candidate/evidence metadata and audit rows
        # are internal indexes, not independently erased top-level artifacts.
        self.assertEqual(5, tombstone["erasure"]["erased_object_count"])

    def test_deleting_summary_is_never_reported_as_active(self) -> None:
        _request, receipt, _, _ = self.start_session()
        session_id = receipt["session_id"]
        with self.backend._connect() as connection:
            connection.execute(
                "UPDATE sessions SET state = 'deleting' WHERE session_id = ?",
                (session_id,),
            )
            row = connection.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            summary = self.backend._session_summary(row)
        self.assertEqual("deleting", summary["retention"]["deletion_status"])
        self.assert_api_error(
            410,
            "SESSION_DELETED",
            lambda: self.backend.get_session(session_id),
        )

    def test_exact_approved_candidate_exports_deterministic_structural_handoff(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.backend.persist_candidate_bundle(
            candidate=candidate,
            evidence_manifest=manifest,
            previews=previews,
        )
        resolved = json.loads(
            self.backend.transition_candidate(
                candidate["candidate_id"],
                if_match=candidate["candidate_digest"],
                idempotency_key="candidate:handoff:resolve",
                body=self.candidate_transition_body(
                    candidate, "resolve_clarification"
                ),
            ).body
        )
        approved = json.loads(
            self.backend.transition_candidate(
                resolved["candidate_id"],
                if_match=resolved["candidate_digest"],
                idempotency_key="candidate:handoff:approve",
                body=self.candidate_transition_body(resolved, "approve"),
            ).body
        )
        self.clock.set(approved["approval"]["approved_at"])
        artifacts = export_approved_candidate(
            candidate=approved,
            evidence_manifest=manifest,
            sdk_build_identity=self.build,
            handoff_build_identity=self.handoff_build_identity(),
            authority={
                "purpose": "implement_approved_ticket",
                "allowed_repositories": ["repo_mobile"],
                "read_authorized_evidence": True,
                "modify_code": True,
                "run_tests": True,
                "external_writes": False,
                "merge": False,
                "deploy": False,
            },
            registry_revision="registry_local_001",
            checked_at=self.clock(),
        )
        self.assertEqual(3, artifacts.handoff["ticket"]["ticket_version"])
        self.assertIsNone(
            artifacts.handoff["supersession"]["supersedes_handoff_digest"]
        )
        self.assertTrue(artifacts.json_bytes.endswith(b"\n"))
        self.assertIn(b"## Canonical JSON", artifacts.markdown_bytes)
        self.assertEqual(sha256_digest(artifacts.json_bytes), artifacts.json_digest)
        self.assertEqual(
            sha256_digest(artifacts.markdown_bytes), artifacts.markdown_digest
        )
        HANDOFF.validate_handoff(artifacts.handoff, executable=False)
        with self.assertRaises(HANDOFF.ContractError) as captured:
            HANDOFF.validate_handoff(artifacts.handoff, executable=True)
        self.assertEqual("TRUST_INPUT_REQUIRED", captured.exception.code)

        missing_binary_identity = self.handoff_build_identity()
        missing_binary_identity["mobile"].pop("native_binary_digest")
        with self.assertRaises(HandoffExportError) as captured:
            export_approved_candidate(
                candidate=approved,
                evidence_manifest=manifest,
                sdk_build_identity=self.build,
                handoff_build_identity=missing_binary_identity,
                authority=artifacts.handoff["authority"],
                registry_revision="registry_local_001",
                checked_at=self.clock(),
            )
        self.assertEqual("HANDOFF_BUILD_INVALID", captured.exception.code)

    def test_candidate_review_is_bound_to_verified_screenshot_bytes(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        inserted = self.backend.persist_candidate_bundle(
            candidate=candidate,
            evidence_manifest=manifest,
            previews=previews,
        )
        self.assertEqual(candidate, inserted)
        self.assertEqual([candidate], self.backend.list_candidates(session_id))

        view = self.backend.get_candidate_evidence(
            candidate["candidate_id"],
            1,
            candidate_digest=candidate["candidate_digest"],
            manifest_digest=manifest["manifest_digest"],
        )
        self.assertEqual(
            set(candidate["evidence_manifest"]["evidence_ids"]),
            {item["evidence_id"] for item in view["items"]},
        )
        self.assertTrue(
            any(event["event_id"] == "event_issue" for event in view["diagnostic_events"])
        )
        self.assertTrue(
            all(
                set(event["evidence_refs"])
                <= set(candidate["evidence_manifest"]["evidence_ids"])
                for event in view["diagnostic_events"]
            )
        )
        preview = self.backend.get_candidate_preview(
            candidate["candidate_id"],
            1,
            "evidence_frame",
            candidate_digest=candidate["candidate_digest"],
            manifest_digest=manifest["manifest_digest"],
        )
        self.assertEqual(previews[0]["body"], preview["body"])

        resolved_response = self.backend.transition_candidate(
            candidate["candidate_id"],
            if_match=candidate["candidate_digest"],
            idempotency_key="candidate:resolve:one",
            body=self.candidate_transition_body(candidate, "resolve_clarification"),
        )
        resolved = json.loads(resolved_response.body)
        self.assertEqual("ready_for_review", resolved["state"])
        self.backend.get_candidate_evidence(
            resolved["candidate_id"],
            resolved["candidate_version"],
            candidate_digest=resolved["candidate_digest"],
            manifest_digest=manifest["manifest_digest"],
        )

        approved_response = self.backend.transition_candidate(
            resolved["candidate_id"],
            if_match=resolved["candidate_digest"],
            idempotency_key="candidate:approve:one",
            body=self.candidate_transition_body(resolved, "approve"),
        )
        approved = json.loads(approved_response.body)
        self.assertEqual("approved", approved["state"])
        self.assertEqual(3, approved["candidate_version"])
        self.assertEqual(
            candidate["evidence_manifest"]["evidence_ids"],
            approved["approval"]["authorized_evidence_ids"],
        )
        self.backend.get_candidate_evidence(
            approved["candidate_id"],
            approved["candidate_version"],
            candidate_digest=approved["candidate_digest"],
            manifest_digest=manifest["manifest_digest"],
        )

    def test_candidate_approval_and_deletion_fail_closed(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.backend.persist_candidate_bundle(
            candidate=candidate,
            evidence_manifest=manifest,
            previews=previews,
        )
        resolved_response = self.backend.transition_candidate(
            candidate["candidate_id"],
            if_match=candidate["candidate_digest"],
            idempotency_key="candidate:resolve:tamper",
            body=self.candidate_transition_body(candidate, "resolve_clarification"),
        )
        resolved = json.loads(resolved_response.body)
        with self.backend._connect() as connection:
            relative = connection.execute(
                "SELECT relative_path FROM tacua_evidence_preview_revisions "
                "WHERE relative_path IS NOT NULL LIMIT 1"
            ).fetchone()[0]
        (self.backend.derived_evidence_dir / relative).write_bytes(b"tampered")
        self.assert_api_error(
            409,
            "STORED_PREVIEW_TAMPERED",
            lambda: self.backend.transition_candidate(
                resolved["candidate_id"],
                if_match=resolved["candidate_digest"],
                idempotency_key="candidate:approve:tamper",
                body=self.candidate_transition_body(resolved, "approve"),
            ),
        )
        self.assertEqual(2, self.backend.get_candidate(candidate["candidate_id"])["candidate_version"])

        tombstone = self.backend.delete_session(session_id)
        self.assertEqual("deleted", tombstone["erasure"]["derived_data"])
        with self.backend._connect() as connection:
            for table in (
                "candidate_heads",
                "candidate_versions",
                "candidate_operations",
                "tacua_candidate_evidence_bindings",
                "tacua_evidence_manifests",
                "tacua_evidence_items",
                "tacua_evidence_preview_revisions",
                "tacua_evidence_file_journal",
                "tacua_evidence_audit",
            ):
                self.assertEqual(
                    0,
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                    table,
                )
        self.assertFalse(any(path.is_file() for path in self.backend.derived_evidence_dir.rglob("*")))

    def test_launch_exact_replay_persists_no_plaintext_secrets(self) -> None:
        request, receipt, original, grant = self.start_session()
        replay = self.backend.exchange_launch_code(copy.deepcopy(request))
        self.assertEqual(200, replay.status)
        self.assertEqual(original, replay.body)
        self.assertNotIn("secret", receipt)
        self.assertNotIn("launch_code", receipt)

        conflicting = copy.deepcopy(request)
        conflicting["requested_at"] = "2026-07-21T09:57:02Z"
        conflicting = seal(conflicting)
        self.assert_api_error(
            409, "IDEMPOTENCY_CONFLICT", lambda: self.backend.exchange_launch_code(conflicting)
        )
        for path in self.config.state_directory.rglob("*"):
            if path.is_file():
                raw = path.read_bytes()
                self.assertNotIn(grant["launch_code"].encode(), raw)
                self.assertNotIn(request["credential"]["secret"].encode(), raw)
                self.assertNotIn(self.admin_secret, raw)

    def test_consumed_launch_replay_survives_grant_ttl(self) -> None:
        request, _receipt, original, _grant = self.start_session()
        self.clock.set("2026-07-21T10:30:00Z")
        replay = self.backend.exchange_launch_code(copy.deepcopy(request))
        self.assertEqual(200, replay.status)
        self.assertEqual(original, replay.body)

    def test_deleted_session_resume_returns_gone_without_retaining_launch_code(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        deletion = fixture("deletion-request")
        deletion.update(
            {
                "session_id": session_id,
                "scope_digest": self.scope["scope_digest"],
                "credential_id": "credential_synthetic",
            }
        )
        deletion = seal(deletion)
        self.clock.set("2026-07-21T10:03:01Z")
        self.backend.delete_session_sdk(
            session_id, deletion["deletion_id"], lifecycle["secret"], deletion
        )
        resume = fixture("receiving-resume-request")
        resume.update(
            {
                "launch_code": "Q" * 43,
                "expected_session_id": session_id,
                "previous_credential_id": "credential_synthetic",
                "build_identity": copy.deepcopy(self.build),
                "scope": copy.deepcopy(self.scope),
            }
        )
        resume = seal(resume)
        self.assert_api_error(
            410, "SESSION_DELETED", lambda: self.backend.exchange_launch_code(resume)
        )

    def test_cross_session_secret_and_scope_cannot_reach_operation_lookup(self) -> None:
        first_request, first_receipt, _, _ = self.start_session()
        _second_request, second_receipt, _, _ = self.start_session(
            credential_id="credential_other_session",
            secret="U" * 43,
            exchange_id="exchange_other_session",
        )
        self.assert_api_error(
            401,
            "SDK_AUTHENTICATION_FAILED",
            lambda: self.backend.preauthorize_sdk_route(
                first_receipt["session_id"], "U" * 43
            ),
        )
        request = fixture("segment-upload-intent")
        content = b"cross session"
        request.update(
            {
                "session_id": first_receipt["session_id"],
                "scope_digest": self.scope["scope_digest"],
                "credential_id": first_request["credential"]["credential_id"],
                "transport": {
                    "content_type": "video/quicktime",
                    "size_bytes": len(content),
                    "content_digest": digest(content),
                },
            }
        )
        request = seal(request)
        self.clock.set("2026-07-21T10:02:00Z")
        self.assert_api_error(
            403,
            "ROUTE_SCOPE_MISMATCH",
            lambda: self.backend.upload_segment(
                second_receipt["session_id"],
                request["sequence"],
                request["segment_id"],
                "U" * 43,
                request,
                io.BytesIO(content),
            ),
        )

    def test_launch_rejects_valid_but_unpinned_build_and_transport(self) -> None:
        self.assert_api_error(
            403,
            "BUILD_NOT_AUTHORIZED",
            lambda: self.backend.create_launch_code(
                {"exchange_kind": "start_session", "build_id": "build_not_registered"}
            ),
        )

        for field, value in (
            ("native_build", "43"),
            ("transport_configuration_digest", "sha256:" + "9" * 64),
        ):
            with self.subTest(field=field):
                grant = self.backend.create_launch_code(
                    {"exchange_kind": "start_session", "build_id": self.build["build_id"]}
                )
                build = copy.deepcopy(self.build)
                build[field] = value
                build = seal(build)
                scope = copy.deepcopy(self.scope)
                scope["build_identity_digest"] = build["build_identity_digest"]
                scope = seal(scope)
                request = fixture("launch-exchange-request")
                request["launch_code"] = grant["launch_code"]
                request["build_identity"] = build
                request["scope"] = scope
                request["exchange_id"] = f"exchange_unpinned_{field}"
                request = seal(request)
                self.assert_api_error(
                    403,
                    "BUILD_NOT_AUTHORIZED",
                    lambda request=request: self.backend.exchange_launch_code(request),
                )

    def test_start_grant_accepts_sdk_post_consent_scope(self) -> None:
        self.assert_api_error(
            400,
            "INVALID_LAUNCH_GRANT",
            lambda: self.backend.create_launch_code(
                {
                    "exchange_kind": "start_session",
                    "build_id": self.build["build_id"],
                    "scope": self.scope,
                }
            ),
        )
        grant = self.backend.create_launch_code(
            {"exchange_kind": "start_session", "build_id": self.build["build_id"]}
        )
        self.assertIn("scope_policy_digest", grant)
        self.assertNotIn("scope_digest", grant)
        scope = copy.deepcopy(self.scope)
        consent_at = self.clock().strftime("%Y-%m-%dT%H:%M:%SZ")
        scope["consent"]["granted_at"] = consent_at
        scope = seal(scope)
        request = fixture("launch-exchange-request")
        request["launch_code"] = grant["launch_code"]
        request["scope"] = scope
        request["requested_at"] = consent_at
        request = seal(request)
        response = self.backend.exchange_launch_code(request)
        self.assertEqual(201, response.status)
        self.assertEqual(scope, response.json()["scope"])

    def test_receiving_rotation_revokes_atomically_and_recovers_historical_receipt(self) -> None:
        launch_request, launch_receipt, _, _ = self.start_session()
        session_id = launch_receipt["session_id"]
        segment_request, _, segment_response = self.store_segment(
            session_id, "credential_synthetic", launch_request["credential"]["secret"]
        )
        _resume_request, resume_receipt, _ = self.resume_session(
            session_id,
            "credential_synthetic",
            state="receiving",
            completion_id=None,
            credential_id="credential_receiving_resume",
            secret="U" * 43,
            exchange_id="exchange_receiving_resume",
            requested_at="2026-07-21T10:02:01Z",
            accepted_at="2026-07-21T10:02:02Z",
        )
        self.assertEqual(
            resume_receipt["issued_at"],
            resume_receipt["previous_credential_revocation"]["revoked_at"],
        )
        unread = io.BytesIO(b"not the original body")
        recovered = self.backend.upload_segment(
            session_id,
            segment_request["sequence"],
            segment_request["segment_id"],
            "U" * 43,
            segment_request,
            unread,
        )
        self.assertEqual(200, recovered.status)
        self.assertEqual(segment_response, recovered.body)
        self.assertEqual(0, unread.tell())
        self.assert_api_error(
            401,
            "SDK_AUTHENTICATION_FAILED",
            lambda: self.backend.preauthorize_sdk_route(
                session_id, launch_request["credential"]["secret"]
            ),
        )

        missing = copy.deepcopy(segment_request)
        missing["upload_id"] = "upload_missing_after_rotation"
        missing["segment_id"] = "segment_missing_after_rotation"
        missing["sequence"] = 1
        missing = seal(missing)
        self.assert_api_error(
            403,
            "OPERATION_NOT_AUTHORIZED",
            lambda: self.backend.upload_segment(
                session_id, 1, missing["segment_id"], "U" * 43, missing, io.BytesIO(b"x")
            ),
        )

    def test_segment_integrity_conflicts_and_sidecar_is_digest_only(self) -> None:
        launch_request, launch_receipt, _, _ = self.start_session()
        session_id = launch_receipt["session_id"]
        request = fixture("segment-upload-intent")
        content = b"real media"
        request.update(
            {
                "session_id": session_id,
                "scope_digest": self.scope["scope_digest"],
                "credential_id": "credential_synthetic",
                "transport": {
                    "content_type": "video/quicktime",
                    "size_bytes": len(content),
                    "content_digest": digest(content),
                },
            }
        )
        request = seal(request)
        self.clock.set("2026-07-21T10:02:00Z")
        self.assert_api_error(
            422,
            "CONTENT_DIGEST_MISMATCH",
            lambda: self.backend.upload_segment(
                session_id,
                0,
                request["segment_id"],
                launch_request["credential"]["secret"],
                request,
                io.BytesIO(b"wrong body"[: len(content)]),
            ),
        )
        self.assertEqual([], self.backend.get_session(session_id)["segment_receipts"])
        _, receipt, _ = self.store_segment(
            session_id, "credential_synthetic", launch_request["credential"]["secret"]
        )
        self.assertEqual("sha256:" + "4" * 64, receipt["sidecar_digest"])
        session_files = [path.name for path in (self.config.state_directory / "objects" / session_id).rglob("*") if path.is_file()]
        self.assertEqual(1, len(session_files))
        self.assertTrue(session_files[0].endswith(".media"))

    def test_full_completion_queues_contract_job_and_is_exactly_replayable(self) -> None:
        lifecycle = self.full_completed_session()
        completion = lifecycle["completion_receipt"]
        self.assertEqual("queued", completion["processing_job"]["status"])
        self.assertEqual([completion["processing_job"]], self.backend.list_jobs())
        replay = self.backend.complete_session(
            lifecycle["launch_receipt"]["session_id"],
            lifecycle["completion_request"]["completion_id"],
            lifecycle["secret"],
            copy.deepcopy(lifecycle["completion_request"]),
        )
        self.assertEqual(200, replay.status)
        self.assertEqual(lifecycle["completion_bytes"], replay.body)
        self.assert_api_error(
            403,
            "REPLAY_NOT_AUTHORIZED",
            lambda: self.backend.upload_segment(
                lifecycle["launch_receipt"]["session_id"],
                0,
                lifecycle["segment_request"]["segment_id"],
                lifecycle["secret"],
                lifecycle["segment_request"],
                io.BytesIO(b"ignored"),
            ),
        )

    def test_completed_resume_recovers_only_bound_completion(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        _request, receipt, _ = self.resume_session(
            session_id,
            "credential_synthetic",
            state="completed",
            completion_id="completion_synthetic",
            credential_id="credential_completed_resume",
            secret="T" * 43,
            exchange_id="exchange_completed_resume",
            requested_at="2026-07-21T10:02:20Z",
            accepted_at="2026-07-21T10:02:21Z",
        )
        self.assertEqual("completion_replay_or_delete_only", receipt["credential"]["state"])
        replay = self.backend.complete_session(
            session_id,
            "completion_synthetic",
            "T" * 43,
            lifecycle["completion_request"],
        )
        self.assertEqual(200, replay.status)
        self.assertEqual(lifecycle["completion_bytes"], replay.body)
        self.assert_api_error(
            403,
            "REPLAY_NOT_AUTHORIZED",
            lambda: self.backend.upload_diagnostic(
                session_id,
                lifecycle["diagnostic_request"]["upload_id"],
                "T" * 43,
                lifecycle["diagnostic_request"],
            ),
        )

    def test_completion_rejects_omitted_durable_receipt_and_sidecar_mismatch(self) -> None:
        launch_request, launch_receipt, _, _ = self.start_session()
        session_id = launch_receipt["session_id"]
        _, first, _ = self.store_segment(
            session_id, "credential_synthetic", launch_request["credential"]["secret"]
        )
        self.store_segment(
            session_id,
            "credential_synthetic",
            launch_request["credential"]["secret"],
            upload_id="upload_segment_second",
            sequence=1,
            segment_id="segment_second",
            content=b"second media",
        )
        _, diagnostic, _ = self.store_diagnostic(
            session_id, "credential_synthetic", launch_request["credential"]["secret"]
        )
        omitted = self.completion_request(
            session_id, "credential_synthetic", [first], [diagnostic]
        )
        self.clock.set("2026-07-21T10:02:06Z")
        self.assert_api_error(
            409,
            "RECEIPT_SET_MISMATCH",
            lambda: self.backend.complete_session(
                session_id, "completion_synthetic", launch_request["credential"]["secret"], omitted
            ),
        )
        tampered = copy.deepcopy(omitted)
        tampered["segment_receipts"][0]["sidecar_digest"] = "sha256:" + "8" * 64
        tampered["segment_receipts"][0] = seal(tampered["segment_receipts"][0])
        tampered = seal(tampered)
        self.assert_api_error(
            422,
            "PROTOCOL_INVALID",
            lambda: self.backend.complete_session(
                session_id, "completion_synthetic", launch_request["credential"]["secret"], tampered
            ),
        )

    def test_sdk_deletion_erases_everything_and_replays_exact_tombstone(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        request = fixture("deletion-request")
        request.update(
            {
                "session_id": session_id,
                "scope_digest": self.scope["scope_digest"],
                "credential_id": "credential_synthetic",
            }
        )
        request = seal(request)
        self.clock.set("2026-07-21T10:03:01Z")
        first = self.backend.delete_session_sdk(
            session_id, request["deletion_id"], lifecycle["secret"], request
        )
        self.assertEqual(201, first.status)
        tombstone = first.json()
        validate_operation_pair(request, tombstone)
        self.assertFalse((self.config.state_directory / "objects" / session_id).exists())
        with closing(sqlite3.connect(self.backend.db_path)) as conn:
            for table in (
                "sessions",
                "credentials",
                "segments",
                "diagnostics",
                "completions",
                "jobs",
                "pending_deletions",
            ):
                self.assertEqual(0, conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM tombstones").fetchone()[0])
        replay = self.backend.delete_session_sdk(
            session_id, request["deletion_id"], lifecycle["secret"], copy.deepcopy(request)
        )
        self.assertEqual(200, replay.status)
        self.assertEqual(first.body, replay.body)
        conflicting = copy.deepcopy(request)
        conflicting["requested_at"] = "2026-07-21T10:03:02Z"
        conflicting = seal(conflicting)
        self.assert_api_error(
            409,
            "IDEMPOTENCY_CONFLICT",
            lambda: self.backend.delete_session_sdk(
                session_id, request["deletion_id"], lifecycle["secret"], conflicting
            ),
        )
        self.assert_api_error(
            410,
            "SESSION_DELETED",
            lambda: self.backend.preauthorize_sdk_route(session_id, lifecycle["secret"]),
        )

    def test_deletion_crash_recovery_finishes_before_restart(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        request = fixture("deletion-request")
        request.update(
            {
                "session_id": session_id,
                "scope_digest": self.scope["scope_digest"],
                "credential_id": "credential_synthetic",
            }
        )
        request = seal(request)
        self.clock.set("2026-07-21T10:03:01Z")
        with patch.object(self.backend, "_erase_session_objects", side_effect=OSError("synthetic")):
            self.assert_api_error(
                500,
                "STORAGE_DELETE_FAILED",
                lambda: self.backend.delete_session_sdk(
                    session_id, request["deletion_id"], lifecycle["secret"], request
                ),
            )
        with closing(sqlite3.connect(self.backend.db_path)) as conn:
            self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM pending_deletions").fetchone()[0])
            self.assertEqual("deleting", conn.execute("SELECT state FROM sessions").fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0])
        restarted = PilotBackend(self.config, self.admin_secret, clock=self.clock)
        self.assert_api_error(
            410,
            "SESSION_DELETED",
            lambda: restarted.get_session(session_id),
        )
        replay = restarted.delete_session_sdk(
            session_id, request["deletion_id"], lifecycle["secret"], request
        )
        self.assertEqual(200, replay.status)

    def test_tombstone_and_replay_verifier_expire_together(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        request = fixture("deletion-request")
        request.update(
            {
                "session_id": session_id,
                "scope_digest": self.scope["scope_digest"],
                "credential_id": "credential_synthetic",
            }
        )
        request = seal(request)
        self.clock.set("2026-07-21T10:03:01Z")
        response = self.backend.delete_session_sdk(
            session_id, request["deletion_id"], lifecycle["secret"], request
        )
        expires = instant(response.json()["tombstone_expires_at"])
        self.clock.set(expires)
        self.assert_api_error(
            410,
            "DELETION_REPLAY_EXPIRED",
            lambda: self.backend.preauthorize_deletion_route(session_id, lifecycle["secret"]),
        )
        with closing(sqlite3.connect(self.backend.db_path)) as conn:
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM tombstones").fetchone()[0])

    def test_retention_boundary_deletes_and_periodic_worker_stops(self) -> None:
        _request, receipt, _, _ = self.start_session()
        session = self.backend.get_session(receipt["session_id"])
        expiry = instant(session["retention"]["raw_media_expires_at"])
        before = self.backend.sweep_expired_sessions(now=expiry - timedelta(seconds=1))
        self.assertEqual([], before["deleted_session_ids"])
        at = self.backend.sweep_expired_sessions(now=expiry)
        self.assertEqual([receipt["session_id"]], at["deleted_session_ids"])

        wait = ControlledRetentionWait()
        other_root = Path(self.temporary.name) / "worker"
        config = PilotConfig(**{**self.config.__dict__, "state_directory": other_root})
        backend = PilotBackend(config, self.admin_secret, clock=self.clock, retention_wait=wait)
        server = create_server(backend, bind_and_activate=False)
        self.assertTrue(wait.waiting.wait(1))
        self.assertTrue(backend.retention_worker_running)
        server.server_close()
        self.assertFalse(backend.retention_worker_running)

    def test_admin_observation_never_exposes_verifiers(self) -> None:
        lifecycle = self.full_completed_session()
        session = self.backend.get_session(lifecycle["launch_receipt"]["session_id"])
        encoded = canonical_json(session)
        self.assertNotIn("verifier", encoded)
        self.assertNotIn(lifecycle["secret"], encoded)
        self.assertEqual(1, len(session["jobs"]))
        self.assertTrue(self.backend.list_audit_events())


class StrictJSONAndConfigTests(unittest.TestCase):
    def test_strict_json_rejects_duplicate_float_unsafe_and_non_nfc(self) -> None:
        bad_values = (
            b'{"a":1,"a":2}',
            b'{"a":1.25}',
            b'{"a":9007199254740992}',
            '{"a":"e\u0301"}'.encode(),
        )
        for raw in bad_values:
            with self.subTest(raw=raw), self.assertRaises((ValueError, InvalidJSONValue)):
                strict_json_loads(raw)
        self.assertEqual({"a": 1, "text": "é"}, strict_json_loads('{"a":1,"text":"é"}'))

    def test_origin_normalization_and_https_boundary(self) -> None:
        self.assertEqual("https://example.com", normalize_backend_origin("HTTPS://Example.COM:443/"))
        self.assertEqual("http://127.0.0.1:8080", normalize_backend_origin("http://127.0.0.1:8080"))
        for value in (
            "http://example.com",
            "https://user@example.com",
            "https://example.com/path",
            "https://example.com?query=1",
        ):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                normalize_backend_origin(value)

    def test_mounted_config_is_closed_and_secret_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "config.json"
            secret_path = root / "secret"
            build = fixture("build-identity")
            scope = fixture("capture-scope")
            document = {
                "organization_id": scope["organization_id"],
                "project_id": scope["project_id"],
                "application_id": scope["application_id"],
                "reviewer_id": "reviewer_owner",
                "build_identity": build,
                "consent_contract": scope["consent"]["policy_version"],
                "backend_origin": "https://qa.tacua.example",
                "state_directory": str(root / "state"),
            }
            config_path.write_text(json.dumps(document), encoding="utf-8")
            secret_path.write_bytes(b"a" * 32 + b"\n")
            config, secret = load_config(config_path, secret_path)
            self.assertEqual(build["transport_configuration_digest"], config.transport_configuration_digest)
            self.assertEqual(b"a" * 32, secret)
            document["unknown"] = True
            config_path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(config_path, secret_path)

    def test_registered_build_must_be_sealed_and_match_transport_pin(self) -> None:
        build = fixture("build-identity")
        scope = fixture("capture-scope")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tampered = copy.deepcopy(build)
            tampered["native_build"] = "43"
            config = PilotConfig(
                organization_id=scope["organization_id"],
                project_id=scope["project_id"],
                application_id=scope["application_id"],
                build_identity=tampered,
                consent_contract=scope["consent"]["policy_version"],
                backend_origin="https://qa.tacua.example",
                state_directory=root / "tampered",
            )
            with self.assertRaisesRegex(ValueError, "valid sealed"):
                PilotBackend(config, b"x" * 32)

            wrong_transport = copy.deepcopy(build)
            wrong_transport["transport_configuration_digest"] = "sha256:" + "9" * 64
            wrong_transport = seal(wrong_transport)
            config = PilotConfig(
                organization_id=scope["organization_id"],
                project_id=scope["project_id"],
                application_id=scope["application_id"],
                build_identity=wrong_transport,
                consent_contract=scope["consent"]["policy_version"],
                backend_origin="https://qa.tacua.example",
                state_directory=root / "wrong-transport",
            )
            with self.assertRaisesRegex(ValueError, "transport configuration"):
                PilotBackend(config, b"x" * 32)

    def test_schema_one_state_is_rejected_with_explicit_reset_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "tacua.sqlite3"
            with closing(sqlite3.connect(database)) as conn:
                conn.execute("CREATE TABLE legacy(value TEXT)")
                conn.execute("PRAGMA user_version = 1")
                conn.commit()
            build = fixture("build-identity")
            scope = fixture("capture-scope")
            config = PilotConfig(
                scope["organization_id"],
                scope["project_id"],
                scope["application_id"],
                build,
                scope["consent"]["policy_version"],
                "https://qa.tacua.example",
                root,
            )
            with self.assertRaisesRegex(ValueError, "empty state directory"):
                PilotBackend(config, b"x" * 32)


class HTTPAdapterTests(BackendHarness):
    def handler(
        self,
        path: str,
        *,
        method: str = "GET",
        authorization: str | None = None,
        body: bytes = b"",
    ) -> PilotRequestHandler:
        handler = object.__new__(PilotRequestHandler)
        handler.path = path
        handler.command = method
        handler.server = SimpleNamespace(backend=self.backend)
        handler.headers = Message()
        handler.close_connection = False
        handler.rfile = io.BytesIO(body)
        handler.wfile = io.BytesIO()
        if authorization is not None:
            handler.headers["Authorization"] = authorization
        if body:
            handler.headers["Content-Length"] = str(len(body))
        return handler

    def test_build_bootstrap_requires_admin_and_rejects_a_body(self) -> None:
        unauthenticated = self.handler("/v1/admin/builds")
        with self.assertRaises(ApiError) as captured:
            unauthenticated._dispatch()
        self.assertEqual(401, captured.exception.status)

        with_body = self.handler(
            "/v1/admin/builds",
            authorization="Bearer " + self.admin_secret.decode("ascii"),
            body=b"x",
        )
        with self.assertRaises(ApiError) as captured:
            with_body._dispatch()
        self.assertEqual("UNEXPECTED_BODY", captured.exception.code)

        handler = self.handler(
            "/v1/admin/builds",
            authorization="Bearer " + self.admin_secret.decode("ascii"),
        )
        sent: list[tuple[int, dict]] = []
        handler._send_json = lambda status, body: sent.append((status, body))
        handler._dispatch()
        self.assertEqual(200, sent[0][0])
        self.assertEqual(
            {
                "builds": [
                    {
                        "build_id": self.build["build_id"],
                        "application_id": self.scope["application_id"],
                        "bundle_identifier": self.build["bundle_identifier"],
                        "native_version": self.build["native_version"],
                        "native_build": self.build["native_build"],
                        "distribution": self.build["distribution"],
                        "build_identity_digest": self.build["build_identity_digest"],
                    }
                ]
            },
            sent[0][1],
        )

    def test_candidate_routes_preserve_exact_etag_and_evidence_bindings(self) -> None:
        lifecycle = self.full_completed_session()
        session_id = lifecycle["launch_receipt"]["session_id"]
        candidate, manifest, previews = self.candidate_bundle(session_id)
        self.backend.persist_candidate_bundle(
            candidate=candidate,
            evidence_manifest=manifest,
            previews=previews,
        )
        authorization = "Bearer " + self.admin_secret.decode("ascii")

        listed = self.handler(
            f"/v1/admin/sessions/{session_id}/candidates",
            authorization=authorization,
        )
        list_responses: list[tuple[int, dict]] = []
        listed._send_json = lambda status, body: list_responses.append((status, body))
        listed._dispatch()
        self.assertEqual([candidate], list_responses[0][1]["candidates"])

        def bound_handler(path: str) -> PilotRequestHandler:
            handler = self.handler(path, authorization=authorization)
            handler.headers["If-Match"] = f'"{candidate["candidate_digest"]}"'
            handler.headers["Tacua-Evidence-Manifest-Digest"] = manifest["manifest_digest"]
            return handler

        evidence = bound_handler(
            f"/v1/admin/candidates/{candidate['candidate_id']}/versions/1/evidence"
        )
        evidence_responses: list[tuple[int, bytes, str, dict[str, str]]] = []
        evidence._send_bytes = lambda status, payload, content_type="application/json", headers=None: evidence_responses.append(
            (status, payload, content_type, headers or {})
        )
        evidence._dispatch()
        evidence_body = json.loads(evidence_responses[0][1])
        self.assertEqual(candidate["candidate_digest"], evidence_body["candidate_digest"])
        self.assertEqual(
            f'"{candidate["candidate_digest"]}"',
            evidence_responses[0][3]["ETag"],
        )

        preview = bound_handler(
            f"/v1/admin/candidates/{candidate['candidate_id']}/versions/1/"
            "evidence/evidence_frame/preview"
        )
        preview_responses: list[tuple[int, bytes, str, dict[str, str]]] = []
        preview._send_bytes = lambda status, payload, content_type="application/json", headers=None: preview_responses.append(
            (status, payload, content_type, headers or {})
        )
        preview._dispatch()
        self.assertEqual(previews[0]["body"], preview_responses[0][1])
        self.assertEqual("image/png", preview_responses[0][2])
        self.assertEqual(
            previews[0]["content_digest"],
            preview_responses[0][3]["Tacua-Content-Digest"],
        )

        transition_body = self.candidate_transition_body(
            candidate, "resolve_clarification"
        )
        transition_bytes = canonical_json(transition_body).encode("utf-8")
        transition = self.handler(
            f"/v1/admin/candidates/{candidate['candidate_id']}/transitions",
            method="POST",
            authorization=authorization,
            body=transition_bytes,
        )
        transition.headers["Content-Type"] = "application/json"
        transition.headers["If-Match"] = f'"{candidate["candidate_digest"]}"'
        transition.headers["Idempotency-Key"] = "candidate:http:resolve"
        transition_responses: list[tuple[int, bytes, str, dict[str, str]]] = []
        transition._send_bytes = lambda status, payload, content_type="application/json", headers=None: transition_responses.append(
            (status, payload, content_type, headers or {})
        )
        transition._dispatch()
        resolved = json.loads(transition_responses[0][1])
        self.assertEqual("ready_for_review", resolved["state"])
        self.assertEqual(
            f'"{resolved["candidate_digest"]}"',
            transition_responses[0][3]["ETag"],
        )
        self.assertEqual(
            sha256_digest(transition_responses[0][1]),
            transition_responses[0][3]["Tacua-Body-Digest"],
        )

        malformed = self.handler(
            f"/v1/admin/candidates/{candidate['candidate_id']}/versions/1/evidence",
            authorization=authorization,
        )
        malformed.headers["If-Match"] = candidate["candidate_digest"]
        malformed.headers["Tacua-Evidence-Manifest-Digest"] = manifest["manifest_digest"]
        with self.assertRaises(ApiError) as captured:
            malformed._dispatch()
        self.assertEqual("CANDIDATE_ETAG_INVALID", captured.exception.code)

    def test_segment_route_reconstructs_exact_canonical_intent(self) -> None:
        launch_request, launch_receipt, _, _ = self.start_session()
        content = b"HTTP media"
        intent = fixture("segment-upload-intent")
        intent.update(
            {
                "session_id": launch_receipt["session_id"],
                "scope_digest": self.scope["scope_digest"],
                "credential_id": "credential_synthetic",
                "transport": {
                    "content_type": "video/quicktime",
                    "size_bytes": len(content),
                    "content_digest": digest(content),
                },
            }
        )
        intent = seal(intent)
        path = (
            f"/v1/sdk/sessions/{intent['session_id']}/segments/"
            f"{intent['sequence']}/{intent['segment_id']}"
        )
        handler = self.handler(
            path,
            method="PUT",
            authorization="Bearer " + launch_request["credential"]["secret"],
            body=content,
        )
        headers = {
            "Tacua-Protocol-Version": PROTOCOL_VERSION,
            "Idempotency-Key": intent["upload_id"],
            "Tacua-Scope-Digest": intent["scope_digest"],
            "Tacua-Credential-ID": intent["credential_id"],
            "Tacua-Sidecar-Digest": intent["sidecar_digest"],
            "Tacua-Intent-Digest": intent["intent_digest"],
            "Tacua-Requested-At": intent["requested_at"],
            "Tacua-Content-Digest": intent["transport"]["content_digest"],
            "Content-Type": intent["transport"]["content_type"],
        }
        for name, value in headers.items():
            handler.headers[name] = value
        sent: list = []
        handler._send_protocol = sent.append
        self.clock.set("2026-07-21T10:02:00Z")
        handler._dispatch()
        self.assertEqual(201, sent[0].status)
        validate(sent[0].json())

    def test_authenticated_routes_reject_before_reading_body(self) -> None:
        _request, receipt, _, _ = self.start_session()

        class ExplodingReader:
            def read(self, _size: int = -1) -> bytes:
                raise AssertionError("body was read before authentication")

        path = f"/v1/sdk/sessions/{receipt['session_id']}/diagnostics/upload_never_read"
        handler = self.handler(path, method="PUT", authorization="Bearer " + "U" * 43)
        handler.headers["Content-Length"] = "10"
        handler.headers["Content-Type"] = "application/json"
        handler.rfile = ExplodingReader()
        with self.assertRaises(ApiError) as captured:
            handler._dispatch()
        self.assertEqual(401, captured.exception.status)

    def test_old_routes_and_path_aliases_are_not_accepted(self) -> None:
        handler = self.handler("/v1/sdk/launch-code-exchanges", method="POST")
        with self.assertRaises(ApiError) as captured:
            handler._dispatch()
        self.assertEqual(404, captured.exception.status)
        for path in (
            "/v1/admin/sessions/%2e%2e",
            "/v1/admin/sessions/../outside",
            "/v1//admin/sessions",
            "/healthz?verbose=true",
            "http://example.invalid/healthz",
        ):
            with self.subTest(path=path), self.assertRaises(ApiError):
                self.handler(path)._path()

    def test_duplicate_headers_and_json_media_type_are_rejected(self) -> None:
        handler = self.handler("/v1/admin/launch-codes", method="POST", body=b"{}")
        handler.headers.add_header("Content-Type", "application/json")
        handler.headers.add_header("Content-Type", "application/json")
        with self.assertRaises(ApiError) as captured:
            handler._read_json(100)
        self.assertEqual("CONTENT_TYPE_REQUIRED", captured.exception.code)

        handler = self.handler("/v1/admin/launch-codes", method="POST", body=b"{}")
        handler.headers["Content-Type"] = "text/plain"
        with self.assertRaises(ApiError) as captured:
            handler._read_json(100)
        self.assertEqual(415, captured.exception.status)


if __name__ == "__main__":
    unittest.main()
