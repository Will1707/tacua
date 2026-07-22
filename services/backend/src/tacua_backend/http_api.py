# SPDX-License-Identifier: Apache-2.0

"""Strict HTTP/1.1 mapping for the frozen Tacua SDK/backend protocol."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .contracts import PROTOCOL_VERSION, canonical_json
from .service import (
    ApiError,
    DuplicateJSONKey,
    InvalidJSONValue,
    LimitedReader,
    PilotBackend,
    SDK_BACKEND_ERROR_CONTRACT,
    SDK_BACKEND_ERROR_MAX_BYTES,
    SDK_BACKEND_ERROR_MEDIA_TYPE,
    StoredResponse,
    strict_json_loads,
)


ID = r"[a-z][a-z0-9_-]{2,63}"
SEQUENCE = r"(?:0|[1-9][0-9]{0,3})"
VERSION = r"[1-9][0-9]{0,15}"


class PilotHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        backend: PilotBackend,
        *,
        bind_and_activate: bool = True,
    ):
        self.backend = backend
        self._retention_started = False
        try:
            backend.start_retention_enforcement()
            self._retention_started = True
            super().__init__(address, PilotRequestHandler, bind_and_activate=bind_and_activate)
        except Exception:
            if self._retention_started:
                backend.stop_retention_enforcement()
                self._retention_started = False
            raise

    def server_close(self) -> None:
        try:
            if self._retention_started:
                self.backend.stop_retention_enforcement()
                self._retention_started = False
        finally:
            super().server_close()


class PilotRequestHandler(BaseHTTPRequestHandler):
    server: PilotHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = "TacuaBackend"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        # BaseHTTPRequestHandler logs raw URLs. Suppression guarantees that a
        # malformed URL cannot leak launch or bearer credentials.
        return

    def handle_expect_100(self) -> bool:
        self.close_connection = True
        self._send_api_error(
            ApiError(
                417,
                "EXPECTATION_NOT_SUPPORTED",
                "100-continue is not supported",
            )
        )
        return False

    @property
    def backend(self) -> PilotBackend:
        return self.server.backend

    def _path(self) -> str:
        parsed = urlsplit(self.path)
        if (
            parsed.scheme
            or parsed.netloc
            or "?" in self.path
            or "#" in self.path
            or parsed.query
            or parsed.fragment
        ):
            raise ApiError(400, "INVALID_PATH", "query strings and fragments are not accepted")
        raw = parsed.path
        if "%" in raw or "\\" in raw or "//" in raw:
            raise ApiError(400, "INVALID_PATH", "request path is invalid")
        if any(part in {".", ".."} for part in raw.split("/")):
            raise ApiError(400, "INVALID_PATH", "request path is invalid")
        return raw

    def _single_header(self, name: str, code: str, maximum: int = 512) -> str:
        values = self.headers.get_all(name) or []
        if len(values) != 1 or not values[0] or len(values[0]) > maximum:
            raise ApiError(400, code, f"one valid {name} header is required")
        return values[0]

    def _page_cursor(self) -> str | None:
        values = self.headers.get_all("Tacua-Page-Cursor") or []
        if not values:
            return None
        if len(values) != 1 or not values[0] or len(values[0]) > 512:
            raise ApiError(
                400,
                "PAGE_CURSOR_INVALID",
                "Tacua-Page-Cursor is invalid",
            )
        return values[0]

    def _bearer(self) -> str | None:
        values = self.headers.get_all("Authorization") or []
        if len(values) != 1 or not values[0].startswith("Bearer "):
            return None
        value = values[0][7:]
        if not value or len(value) > 4096 or any(char.isspace() for char in value):
            return None
        return value

    def _admin(self) -> None:
        self.backend.authenticate_admin(self._bearer())

    def _entity_tag(self) -> str:
        value = self._single_header("If-Match", "CANDIDATE_ETAG_REQUIRED", 80)
        match = re.fullmatch(r'"(sha256:[a-f0-9]{64})"', value)
        if match is None:
            raise ApiError(
                400,
                "CANDIDATE_ETAG_INVALID",
                "If-Match must contain one quoted Tacua candidate digest",
            )
        return match.group(1)

    def _evidence_manifest_digest(self) -> str:
        value = self._single_header(
            "Tacua-Evidence-Manifest-Digest",
            "EVIDENCE_MANIFEST_DIGEST_REQUIRED",
            80,
        )
        if re.fullmatch(r"sha256:[a-f0-9]{64}", value) is None:
            raise ApiError(
                400,
                "EVIDENCE_MANIFEST_DIGEST_INVALID",
                "Tacua-Evidence-Manifest-Digest is invalid",
            )
        return value

    def _content_length(self, maximum: int) -> int:
        if self.headers.get("Transfer-Encoding") is not None:
            raise ApiError(400, "TRANSFER_ENCODING_NOT_ALLOWED", "chunked request bodies are not accepted")
        values = self.headers.get_all("Content-Length") or []
        if len(values) != 1 or re.fullmatch(r"[0-9]{1,10}", values[0]) is None:
            raise ApiError(411, "CONTENT_LENGTH_REQUIRED", "one valid Content-Length is required")
        length = int(values[0])
        if length < 1 or length > maximum:
            raise ApiError(413, "CONTENT_SIZE_NOT_ALLOWED", "request body exceeds the configured limit")
        return length

    def _require_json_content_type(self) -> None:
        if self._single_header("Content-Type", "CONTENT_TYPE_REQUIRED") != "application/json":
            raise ApiError(415, "CONTENT_TYPE_NOT_ALLOWED", "JSON requests require application/json")

    def _read_json(self, maximum: int) -> Any:
        self._require_json_content_type()
        length = self._content_length(maximum)
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ApiError(400, "CONTENT_LENGTH_MISMATCH", "request body length does not match Content-Length")
        try:
            return strict_json_loads(raw)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            DuplicateJSONKey,
            InvalidJSONValue,
        ) as exc:
            raise ApiError(400, "INVALID_JSON", "request body must be strict canonical-compatible JSON") from exc

    def _send_bytes(
        self,
        status: int,
        payload: bytes,
        content_type: str = "application/json",
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (headers or {}).items():
            if (
                re.fullmatch(r"[A-Za-z0-9-]{1,64}", name) is None
                or not value
                or len(value) > 512
                or "\r" in value
                or "\n" in value
            ):
                raise RuntimeError("unsafe internal response header")
            self.send_header(name, value)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, status: int, body: Any) -> None:
        self._send_bytes(status, canonical_json(body).encode("utf-8"))

    def _send_protocol(self, response: StoredResponse) -> None:
        self._send_bytes(response.status, response.body)

    def _send_api_error(self, error: ApiError) -> None:
        reconciliation = error.sdk_reconciliation
        if reconciliation is None:
            self._send_json(
                error.status,
                {"error": {"code": error.code, "message": error.message}},
            )
            return
        document = {
            "contract_version": SDK_BACKEND_ERROR_CONTRACT,
            "media_type": SDK_BACKEND_ERROR_MEDIA_TYPE,
            "protocol_version": PROTOCOL_VERSION,
            "error": {
                "code": error.code,
                "message": error.message,
                "reconciliation": reconciliation.as_dict(),
            },
        }
        payload = canonical_json(document).encode("utf-8")
        if len(payload) > SDK_BACKEND_ERROR_MAX_BYTES:
            # All fields are internally constructed and independently bounded.
            # Preserve a content-free failure if that invariant ever regresses.
            self._send_json(
                500,
                {"error": {"code": "INTERNAL_ERROR", "message": "request failed"}},
            )
            return
        self._send_bytes(error.status, payload, SDK_BACKEND_ERROR_MEDIA_TYPE)

    def _dispatch(self) -> None:
        path = self._path()
        if self.command in {"GET", "DELETE"} and (
            self.headers.get("Transfer-Encoding") is not None
            or any(value != "0" for value in (self.headers.get_all("Content-Length") or []))
        ):
            raise ApiError(400, "UNEXPECTED_BODY", "this request method does not accept a body")

        if self.command == "GET" and path == "/healthz":
            self._send_json(200, self.backend.health())
            return
        if self.command == "GET" and path == "/version":
            self._send_json(
                200,
                {
                    "service": "tacua-backend",
                    "version": __version__,
                    "protocol_version": PROTOCOL_VERSION,
                },
            )
            return

        if self.command == "GET" and path == "/v1/admin/builds":
            self._admin()
            self._send_json(200, {"builds": self.backend.list_builds()})
            return
        if self.command == "POST" and path == "/v1/admin/launch-codes":
            self._admin()
            self._send_json(201, self.backend.create_launch_code(self._read_json(2_097_152)))
            return
        if self.command == "POST" and path == "/v1/sdk/launch-exchanges":
            self._send_protocol(self.backend.exchange_launch_code(self._read_json(2_097_152)))
            return

        segment = re.fullmatch(
            rf"/v1/sdk/sessions/(?P<session_id>{ID})/segments/(?P<sequence>{SEQUENCE})/(?P<segment_id>{ID})",
            path,
        )
        if self.command == "PUT" and segment:
            session_id = segment.group("session_id")
            bearer = self._bearer()
            self.backend.preauthorize_sdk_route(session_id, bearer)
            protocol = self._single_header("Tacua-Protocol-Version", "PROTOCOL_VERSION_REQUIRED")
            if protocol != PROTOCOL_VERSION:
                raise ApiError(422, "UNSUPPORTED_PROTOCOL", "Tacua-Protocol-Version is unsupported")
            length = self._content_length(self.backend.config.max_segment_bytes)
            intent = {
                "protocol_version": protocol,
                "message_type": "segment_upload_intent",
                "upload_id": self._single_header("Idempotency-Key", "IDEMPOTENCY_KEY_REQUIRED"),
                "session_id": session_id,
                "scope_digest": self._single_header("Tacua-Scope-Digest", "SCOPE_DIGEST_REQUIRED"),
                "credential_id": self._single_header("Tacua-Credential-ID", "CREDENTIAL_ID_REQUIRED"),
                "sequence": int(segment.group("sequence")),
                "segment_id": segment.group("segment_id"),
                "transport": {
                    "content_type": self._single_header("Content-Type", "CONTENT_TYPE_REQUIRED"),
                    "size_bytes": length,
                    "content_digest": self._single_header(
                        "Tacua-Content-Digest", "CONTENT_DIGEST_REQUIRED"
                    ),
                },
                "sidecar_digest": self._single_header(
                    "Tacua-Sidecar-Digest", "SIDECAR_DIGEST_REQUIRED"
                ),
                "requested_at": self._single_header("Tacua-Requested-At", "REQUESTED_AT_REQUIRED"),
                "intent_digest": self._single_header("Tacua-Intent-Digest", "INTENT_DIGEST_REQUIRED"),
            }
            limited = LimitedReader(self.rfile, length)
            response = self.backend.upload_segment(
                session_id,
                int(segment.group("sequence")),
                segment.group("segment_id"),
                bearer,
                intent,
                limited,
            )
            if limited.remaining:
                # Exact replay can be resolved before consuming a large body.
                self.close_connection = True
            self._send_protocol(response)
            return

        diagnostic = re.fullmatch(
            rf"/v1/sdk/sessions/(?P<session_id>{ID})/diagnostics/(?P<upload_id>{ID})",
            path,
        )
        if self.command == "PUT" and diagnostic:
            bearer = self._bearer()
            self.backend.preauthorize_sdk_route(diagnostic.group("session_id"), bearer)
            body = self._read_json(self.backend.config.max_diagnostic_bytes + 65_536)
            self._send_protocol(
                self.backend.upload_diagnostic(
                    diagnostic.group("session_id"), diagnostic.group("upload_id"), bearer, body
                )
            )
            return

        completion = re.fullmatch(
            rf"/v1/sdk/sessions/(?P<session_id>{ID})/completions/(?P<completion_id>{ID})",
            path,
        )
        if self.command == "PUT" and completion:
            bearer = self._bearer()
            self.backend.preauthorize_sdk_route(completion.group("session_id"), bearer)
            body = self._read_json(self.backend.config.max_completion_bytes)
            self._send_protocol(
                self.backend.complete_session(
                    completion.group("session_id"),
                    completion.group("completion_id"),
                    bearer,
                    body,
                )
            )
            return

        deletion = re.fullmatch(
            rf"/v1/sdk/sessions/(?P<session_id>{ID})/deletions/(?P<deletion_id>{ID})",
            path,
        )
        if self.command == "PUT" and deletion:
            bearer = self._bearer()
            self.backend.preauthorize_deletion_route(deletion.group("session_id"), bearer)
            body = self._read_json(65_536)
            self._send_protocol(
                self.backend.delete_session_sdk(
                    deletion.group("session_id"), deletion.group("deletion_id"), bearer, body
                )
            )
            return

        if self.command == "GET" and path == "/v1/admin/sessions":
            self._admin()
            self._send_json(200, self.backend.list_sessions(self._page_cursor()))
            return
        admin_session_candidates = re.fullmatch(
            rf"/v1/admin/sessions/(?P<session_id>{ID})/candidates", path
        )
        if admin_session_candidates and self.command == "GET":
            self._admin()
            self._send_json(
                200,
                self.backend.list_candidates(
                    admin_session_candidates.group("session_id"),
                    self._page_cursor(),
                ),
            )
            return

        candidate_handoff = re.fullmatch(
            rf"/v1/admin/candidates/(?P<candidate_id>{ID})"
            rf"(?:/versions/(?P<version>{VERSION}))?/handoff\.(?P<format>json|md)",
            path,
        )
        if candidate_handoff and self.command == "GET":
            self._admin()
            raw_version = candidate_handoff.group("version")
            handoff = self.backend.get_candidate_handoff(
                candidate_handoff.group("candidate_id"),
                None if raw_version is None else int(raw_version),
            )
            markdown = candidate_handoff.group("format") == "md"
            body = handoff.markdown_bytes if markdown else handoff.json_bytes
            body_digest = (
                handoff.markdown_digest if markdown else handoff.json_digest
            )
            self._send_bytes(
                200,
                body,
                "text/markdown; charset=utf-8"
                if markdown
                else "application/vnd.tacua.approved-handoff+json;version=1.1.0",
                headers={
                    "ETag": f'"{body_digest}"',
                    "Tacua-Body-Digest": body_digest,
                    "Tacua-Handoff-Digest": handoff.handoff_digest,
                    "Tacua-Candidate-Digest": handoff.candidate_digest,
                    "Tacua-Candidate-Version": str(handoff.candidate_version),
                },
            )
            return

        candidate_preview = re.fullmatch(
            rf"/v1/admin/candidates/(?P<candidate_id>{ID})/versions/"
            rf"(?P<version>{VERSION})/evidence/(?P<evidence_id>{ID})/preview",
            path,
        )
        if candidate_preview and self.command == "GET":
            self._admin()
            candidate_digest = self._entity_tag()
            manifest_digest = self._evidence_manifest_digest()
            preview = self.backend.get_candidate_preview(
                candidate_preview.group("candidate_id"),
                int(candidate_preview.group("version")),
                candidate_preview.group("evidence_id"),
                candidate_digest=candidate_digest,
                manifest_digest=manifest_digest,
            )
            self._send_bytes(
                200,
                preview["body"],
                preview["content_type"],
                headers={
                    "Tacua-Content-Digest": preview["content_digest"],
                    "Tacua-Candidate-Digest": candidate_digest,
                    "Tacua-Evidence-Manifest-Digest": manifest_digest,
                },
            )
            return

        candidate_evidence = re.fullmatch(
            rf"/v1/admin/candidates/(?P<candidate_id>{ID})/versions/"
            rf"(?P<version>{VERSION})/evidence",
            path,
        )
        if candidate_evidence and self.command == "GET":
            self._admin()
            candidate_digest = self._entity_tag()
            manifest_digest = self._evidence_manifest_digest()
            evidence = self.backend.get_candidate_evidence(
                candidate_evidence.group("candidate_id"),
                int(candidate_evidence.group("version")),
                candidate_digest=candidate_digest,
                manifest_digest=manifest_digest,
            )
            self._send_bytes(
                200,
                canonical_json(evidence).encode("utf-8"),
                headers={
                    "ETag": f'"{candidate_digest}"',
                    "Tacua-Evidence-Manifest-Digest": manifest_digest,
                },
            )
            return

        candidate_transition = re.fullmatch(
            rf"/v1/admin/candidates/(?P<candidate_id>{ID})/transitions", path
        )
        if candidate_transition and self.command == "POST":
            self._admin()
            response = self.backend.transition_candidate(
                candidate_transition.group("candidate_id"),
                if_match=self._entity_tag(),
                idempotency_key=self._single_header(
                    "Idempotency-Key", "IDEMPOTENCY_KEY_REQUIRED"
                ),
                body=self._read_json(1_048_576),
            )
            self._send_bytes(
                response.status,
                response.body,
                headers={
                    "ETag": f'"{response.candidate_digest}"',
                    "Tacua-Body-Digest": response.body_digest,
                },
            )
            return

        admin_candidate = re.fullmatch(
            rf"/v1/admin/candidates/(?P<candidate_id>{ID})", path
        )
        if admin_candidate and self.command == "GET":
            self._admin()
            candidate = self.backend.get_candidate(
                admin_candidate.group("candidate_id")
            )
            self._send_bytes(
                200,
                canonical_json(candidate).encode("utf-8"),
                headers={"ETag": f'"{candidate["candidate_digest"]}"'},
            )
            return

        admin_session = re.fullmatch(rf"/v1/admin/sessions/(?P<session_id>{ID})", path)
        if admin_session and self.command == "GET":
            self._admin()
            self._send_json(200, self.backend.get_session(admin_session.group("session_id")))
            return
        if admin_session and self.command == "DELETE":
            self._admin()
            self._send_json(200, self.backend.delete_session(admin_session.group("session_id")))
            return

        if self.command == "GET" and path == "/v1/admin/jobs":
            self._admin()
            self._send_json(200, self.backend.list_jobs(self._page_cursor()))
            return
        admin_job = re.fullmatch(rf"/v1/admin/jobs/(?P<job_id>{ID})", path)
        if admin_job and self.command == "GET":
            self._admin()
            self._send_json(200, self.backend.get_job(admin_job.group("job_id")))
            return
        if self.command == "GET" and path == "/v1/admin/audit-events":
            self._admin()
            self._send_json(200, self.backend.list_audit_events(self._page_cursor()))
            return

        raise ApiError(404, "NOT_FOUND", "route was not found")

    def _handle(self) -> None:
        try:
            self._dispatch()
        except ApiError as exc:
            self.close_connection = True
            self._send_api_error(exc)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:
            # Exception details can contain paths or attacker-provided values.
            self.close_connection = True
            self._send_json(500, {"error": {"code": "INTERNAL_ERROR", "message": "request failed"}})

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle()

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle()


def create_server(
    backend: PilotBackend,
    host: str | None = None,
    port: int | None = None,
    *,
    bind_and_activate: bool = True,
) -> PilotHTTPServer:
    return PilotHTTPServer(
        (
            host if host is not None else backend.config.listen_host,
            port if port is not None else backend.config.listen_port,
        ),
        backend,
        bind_and_activate=bind_and_activate,
    )
