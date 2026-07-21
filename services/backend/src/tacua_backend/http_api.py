"""Small HTTP/1.1 adapter for the Tacua pilot backend."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .service import ApiError, DuplicateJSONKey, LimitedReader, PilotBackend, strict_json_loads


SESSION_PATH = r"(?P<session_id>[a-z][a-z0-9_-]{2,63})"
JOB_PATH = r"(?P<job_id>[a-z][a-z0-9_-]{2,63})"
ENVELOPE_PATH = r"(?P<envelope_id>[a-z][a-z0-9_-]{2,63})"


class PilotHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], backend: PilotBackend):
        self.backend = backend
        super().__init__(address, PilotRequestHandler)


class PilotRequestHandler(BaseHTTPRequestHandler):
    server: PilotHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = "TacuaPilot"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        # BaseHTTPRequestHandler includes the raw URL in logs.  Suppress it so
        # credentials can never be leaked if a caller constructs a bad URL.
        return

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
        parts = raw.split("/")
        if any(part in (".", "..") for part in parts):
            raise ApiError(400, "INVALID_PATH", "request path is invalid")
        return raw

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

    def _content_length(self, maximum: int) -> int:
        if self.headers.get("Transfer-Encoding") is not None:
            raise ApiError(400, "TRANSFER_ENCODING_NOT_ALLOWED", "chunked request bodies are not accepted")
        values = self.headers.get_all("Content-Length") or []
        if len(values) != 1 or not values[0].isdigit():
            raise ApiError(411, "CONTENT_LENGTH_REQUIRED", "one valid Content-Length is required")
        value = int(values[0])
        if value < 1 or value > maximum:
            raise ApiError(413, "CONTENT_SIZE_NOT_ALLOWED", "request body exceeds the configured limit")
        return value

    def _single_header(self, name: str, error_code: str) -> str:
        values = self.headers.get_all(name) or []
        if len(values) != 1 or not values[0] or len(values[0]) > 512:
            raise ApiError(400, error_code, f"one valid {name} header is required")
        return values[0]

    def _read_json(self, maximum: int = 1_048_576) -> Any:
        length = self._content_length(maximum)
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ApiError(400, "CONTENT_LENGTH_MISMATCH", "request body length does not match Content-Length")
        try:
            return strict_json_loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJSONKey) as exc:
            raise ApiError(400, "INVALID_JSON", "request body must be valid UTF-8 JSON") from exc

    def _send_json(self, status: int, body: Any) -> None:
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _dispatch(self) -> None:
        path = self._path()
        if self.command in ("GET", "DELETE") and (
            self.headers.get("Transfer-Encoding") is not None
            or any(value != "0" for value in (self.headers.get_all("Content-Length") or []))
        ):
            raise ApiError(400, "UNEXPECTED_BODY", "this request method does not accept a body")

        if self.command == "GET" and path == "/healthz":
            self._send_json(200, self.backend.health())
            return
        if self.command == "GET" and path == "/version":
            self._send_json(200, {"service": "tacua-pilot-backend", "version": __version__})
            return

        if self.command == "POST" and path == "/v1/admin/launch-codes":
            self._admin()
            body = self._read_json()
            if not isinstance(body, dict) or set(body) != {"scope"}:
                raise ApiError(400, "INVALID_REQUEST", "launch-code fields are invalid")
            self._send_json(201, self.backend.create_launch_code(body["scope"]))
            return
        if self.command == "POST" and path == "/v1/sdk/launch-code-exchanges":
            self._send_json(201, self.backend.exchange_launch_code(self._read_json()))
            return

        match = re.fullmatch(rf"/v1/sdk/sessions/{SESSION_PATH}/segments/(?P<sequence>[0-9]+)", path)
        if self.command == "PUT" and match:
            upload_token = self._bearer()
            self.backend.check_upload_authorization(match.group("session_id"), upload_token)
            segment_id = self._single_header("X-Tacua-Segment-ID", "SEGMENT_ID_REQUIRED")
            expected_digest = self._single_header("X-Content-SHA256", "CONTENT_DIGEST_REQUIRED")
            content_type = self._single_header("Content-Type", "CONTENT_TYPE_REQUIRED")
            length = self._content_length(self.backend.config.max_segment_bytes)
            receipt = self.backend.upload_segment(
                match.group("session_id"),
                int(match.group("sequence")),
                segment_id,
                upload_token,
                LimitedReader(self.rfile, length),
                length,
                expected_digest,
                content_type,
            )
            self._send_json(200 if receipt["idempotent_retry"] else 201, receipt)
            return

        match = re.fullmatch(rf"/v1/sdk/sessions/{SESSION_PATH}/diagnostics/{ENVELOPE_PATH}", path)
        if self.command == "PUT" and match:
            upload_token = self._bearer()
            self.backend.check_upload_authorization(match.group("session_id"), upload_token)
            expected_digest = self._single_header("X-Content-SHA256", "CONTENT_DIGEST_REQUIRED")
            length = self._content_length(self.backend.config.max_diagnostic_bytes)
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ApiError(400, "CONTENT_LENGTH_MISMATCH", "request body length does not match Content-Length")
            receipt = self.backend.upload_diagnostic(
                match.group("session_id"),
                match.group("envelope_id"),
                upload_token,
                raw,
                expected_digest,
            )
            self._send_json(200 if receipt["idempotent_retry"] else 201, receipt)
            return

        match = re.fullmatch(rf"/v1/sdk/sessions/{SESSION_PATH}/completion", path)
        if self.command == "POST" and match:
            upload_token = self._bearer()
            self.backend.check_completion_authorization(match.group("session_id"), upload_token)
            job = self.backend.complete_session(match.group("session_id"), upload_token, self._read_json())
            self._send_json(202, job)
            return

        if path == "/v1/admin/sessions" and self.command == "GET":
            self._admin()
            self._send_json(200, {"sessions": self.backend.list_sessions()})
            return
        match = re.fullmatch(rf"/v1/admin/sessions/{SESSION_PATH}", path)
        if match and self.command == "GET":
            self._admin()
            self._send_json(200, self.backend.get_session(match.group("session_id")))
            return
        if match and self.command == "DELETE":
            self._admin()
            self._send_json(202, self.backend.delete_session(match.group("session_id")))
            return

        if path == "/v1/admin/jobs" and self.command == "GET":
            self._admin()
            self._send_json(200, {"jobs": self.backend.list_jobs()})
            return
        match = re.fullmatch(rf"/v1/admin/jobs/{JOB_PATH}", path)
        if match and self.command == "GET":
            self._admin()
            self._send_json(200, self.backend.get_job(match.group("job_id")))
            return
        if path == "/v1/admin/audit-events" and self.command == "GET":
            self._admin()
            self._send_json(200, {"events": self.backend.list_audit_events()})
            return

        raise ApiError(404, "NOT_FOUND", "route was not found")

    def _handle(self) -> None:
        try:
            self._dispatch()
        except ApiError as exc:
            self.close_connection = True
            self._send_json(exc.status, {"error": {"code": exc.code, "message": exc.message}})
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
            return
        except Exception:
            # Never serialize exception text: it can contain filesystem details
            # or credential-bearing data supplied by a client.
            self.close_connection = True
            self._send_json(500, {"error": {"code": "INTERNAL_ERROR", "message": "request failed"}})

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle()

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle()


def create_server(backend: PilotBackend, host: str | None = None, port: int | None = None) -> PilotHTTPServer:
    return PilotHTTPServer(
        (host if host is not None else backend.config.listen_host, port if port is not None else backend.config.listen_port),
        backend,
    )
