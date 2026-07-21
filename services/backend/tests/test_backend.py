# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
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
from tacua_backend.service import (  # noqa: E402
    ApiError,
    InvalidJSONValue,
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
        request["exchange_id"] = exchange_id
        request["launch_code"] = grant["launch_code"]
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


class BackendProtocolTests(BackendHarness):

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
        scope["consent"]["granted_at"] = "2026-07-21T09:57:00Z"
        scope = seal(scope)
        request = fixture("launch-exchange-request")
        request["launch_code"] = grant["launch_code"]
        request["scope"] = scope
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
        self.assertEqual("deleted", restarted.get_session(session_id)["state"])
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
