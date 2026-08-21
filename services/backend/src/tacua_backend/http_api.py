# SPDX-License-Identifier: Apache-2.0

"""Strict HTTP/1.1 mapping for the frozen Tacua SDK/backend protocol."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import re
from typing import Any, NoReturn
from urllib.parse import urlsplit

from . import __version__
from .config import DIAGNOSTIC_REQUEST_OVERHEAD_ALLOWANCE_BYTES
from .contracts import PROTOCOL_VERSION, canonical_json
from .service import (
    AuthenticatedReviewer,
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
REVIEWER_COOKIE_NAME = "__Host-tacua-reviewer"
REVIEWER_CSRF_HEADER = "Tacua-CSRF-Token"
REVIEWER_SESSION_COOKIE_MAX_AGE = 2_592_000
REVIEWER_READ_SCOPE = "reviewer.read"
REVIEWER_LAUNCH_SCOPE = "reviewer.launch"
REVIEWER_WRITE_SCOPE = "reviewer.write"


def _reviewer_route_alias(
    method: str,
    path: str,
) -> tuple[str, str, bool] | None:
    """Map only explicitly reviewer-safe routes onto legacy service handlers."""

    if method == "GET":
        exact = {
            "/v1/reviewer/bootstrap": "/v1/admin/reviewer-bootstrap",
            "/v1/reviewer/builds": "/v1/admin/builds",
            "/v1/reviewer/sessions": "/v1/admin/sessions",
            "/v1/reviewer/jobs": "/v1/admin/jobs",
            "/v1/reviewer/audit-events": "/v1/admin/audit-events",
        }
        if path in exact:
            return exact[path], REVIEWER_READ_SCOPE, False
        patterns = (
            rf"/v1/reviewer/sessions/{ID}",
            rf"/v1/reviewer/sessions/{ID}/candidates",
            rf"/v1/reviewer/jobs/{ID}",
            rf"/v1/reviewer/candidates/{ID}",
            rf"/v1/reviewer/candidates/{ID}/supersession",
            rf"/v1/reviewer/candidates/{ID}/versions/{VERSION}/evidence",
            rf"/v1/reviewer/candidates/{ID}/versions/{VERSION}/evidence/{ID}/preview",
            rf"/v1/reviewer/candidates/{ID}(?:/versions/{VERSION})?/handoff\.(?:json|md)",
        )
        if any(re.fullmatch(pattern, path) for pattern in patterns):
            return path.replace("/v1/reviewer/", "/v1/admin/", 1), REVIEWER_READ_SCOPE, False
    elif method == "POST":
        if path == "/v1/reviewer/launch-codes":
            return "/v1/admin/launch-codes", REVIEWER_LAUNCH_SCOPE, True
        if path == "/v1/reviewer/candidate-replacements" or re.fullmatch(
            rf"/v1/reviewer/candidates/{ID}/transitions", path
        ):
            return path.replace("/v1/reviewer/", "/v1/admin/", 1), REVIEWER_WRITE_SCOPE, True
    return None


def _pairing_request_document(pairing: Any) -> dict[str, Any]:
    return {
        "pairing_id": pairing.pairing_id,
        "pairing_token": pairing.pairing_token,
        "human_code": pairing.human_code,
        "device_label": pairing.device_label,
        "client_kind": pairing.client_kind,
        "created_at": pairing.created_at,
        "expires_at": pairing.expires_at,
    }


def _approved_pairing_document(pairing: Any) -> dict[str, Any]:
    return {
        "pairing_id": pairing.pairing_id,
        "device_label": pairing.device_label,
        "client_kind": pairing.client_kind,
        "scopes": list(pairing.scopes),
        "created_at": pairing.created_at,
        "approved_at": pairing.approved_at,
        "expires_at": pairing.expires_at,
    }


def _reviewer_session_document(session: Any) -> dict[str, Any]:
    return {
        "session_id": session.session_id,
        "reviewer_id": session.reviewer_id,
        "device_label": session.device_label,
        "client_kind": session.client_kind,
        "scopes": list(session.scopes),
        "created_at": session.created_at,
        "expires_at": session.expires_at,
        "revoked_at": session.revoked_at,
    }


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
        if getattr(self, "_reviewer_alias_authorized", False):
            return
        self.backend.authenticate_admin(self._bearer())

    def _reviewer_id(self) -> str:
        values = self.headers.get_all("Tacua-Reviewer-ID") or []
        if len(values) != 1 or not values[0] or len(values[0]) > 64:
            raise ApiError(
                400,
                "REVIEWER_ID_REQUIRED",
                "one valid reviewer identity header is required",
            )
        reviewer_id = values[0]
        if re.fullmatch(ID, reviewer_id) is None:
            raise ApiError(
                400,
                "REVIEWER_ID_INVALID",
                "reviewer identity header is invalid",
            )
        return reviewer_id

    @staticmethod
    def _reviewer_authentication_failed() -> NoReturn:
        raise ApiError(
            401,
            "REVIEWER_AUTHENTICATION_FAILED",
            "reviewer authentication failed",
        )

    def _reviewer_cookie(self) -> str | None:
        values = self.headers.get_all("Cookie") or []
        if not values:
            return None
        if len(values) != 1 or not values[0] or len(values[0]) > 8_192:
            self._reviewer_authentication_failed()
        found: str | None = None
        for item in values[0].split(";"):
            pair = item.strip()
            if not pair or "=" not in pair:
                self._reviewer_authentication_failed()
            name, value = pair.split("=", 1)
            if re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", name) is None:
                self._reviewer_authentication_failed()
            if name != REVIEWER_COOKIE_NAME:
                continue
            if (
                found is not None
                or not value
                or len(value) > 256
                or re.fullmatch(r"[A-Za-z0-9_.-]+", value) is None
            ):
                self._reviewer_authentication_failed()
            found = value
        return found

    def _reviewer(
        self,
        required_scope: str,
    ) -> AuthenticatedReviewer:
        authorization_values = self.headers.get_all("Authorization") or []
        cookie = self._reviewer_cookie()
        if authorization_values and cookie is not None:
            self._reviewer_authentication_failed()
        bearer = self._bearer()
        if authorization_values and bearer is None:
            self._reviewer_authentication_failed()

        capabilities = tuple(
            self.headers.get_all("Tailscale-App-Capabilities") or []
        )
        capability_principal = self.backend.authenticate_tailscale_reviewer(
            capabilities,
            required_scope=required_scope,
        )
        fallback = bearer if authorization_values else cookie

        if self.backend.config.reviewer_auth.mode == "legacy_admin":
            return self.backend.authenticate_legacy_reviewer(
                fallback,
                required_scope=required_scope,
            )
        if fallback is not None:
            try:
                return self.backend.authenticate_reviewer_session(
                    fallback,
                    required_scope=required_scope,
                )
            except ApiError as error:
                if (
                    authorization_values
                    or capability_principal is None
                    or error.status != 401
                ):
                    raise
        if capability_principal is not None:
            return capability_principal
        self._reviewer_authentication_failed()

    def _reviewer_origin(self) -> None:
        values = self.headers.get_all("Origin") or []
        if len(values) != 1 or values[0] != self.backend.config.backend_origin:
            raise ApiError(
                403,
                "REVIEWER_ORIGIN_FORBIDDEN",
                "reviewer request origin is not authorized",
            )

    def _optional_native_origin(self) -> None:
        values = self.headers.get_all("Origin") or []
        if not values:
            return
        if len(values) != 1 or values[0] != self.backend.config.backend_origin:
            raise ApiError(
                403,
                "REVIEWER_ORIGIN_FORBIDDEN",
                "reviewer request origin is not authorized",
            )

    def _reviewer_csrf(self, principal: AuthenticatedReviewer) -> None:
        self._reviewer_origin()
        values = self.headers.get_all(REVIEWER_CSRF_HEADER) or []
        expected = self.backend.reviewer_csrf_token(principal)
        if (
            len(values) != 1
            or not values[0]
            or len(values[0]) > 128
            or not hmac.compare_digest(values[0], expected)
        ):
            raise ApiError(
                403,
                "REVIEWER_CSRF_FORBIDDEN",
                "reviewer request CSRF token is not authorized",
            )

    def _reviewer_principal_document(
        self,
        principal: AuthenticatedReviewer,
    ) -> dict[str, Any]:
        return {
            "reviewer_id": principal.reviewer_id,
            "auth_kind": principal.auth_kind,
            "session_id": principal.session_id,
            "device_label": principal.device_label,
            "client_kind": principal.client_kind,
            "scopes": list(principal.scopes),
            "expires_at": principal.expires_at,
            "csrf_token": self.backend.reviewer_csrf_token(principal),
        }

    @staticmethod
    def _set_reviewer_cookie(token: str) -> str:
        if not token or len(token) > 256 or re.fullmatch(r"[A-Za-z0-9_.-]+", token) is None:
            raise RuntimeError("unsafe internal reviewer session token")
        return (
            f"{REVIEWER_COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; "
            f"SameSite=Strict; Max-Age={REVIEWER_SESSION_COOKIE_MAX_AGE}"
        )

    @staticmethod
    def _clear_reviewer_cookie() -> str:
        return (
            f"{REVIEWER_COOKIE_NAME}=; Path=/; Secure; HttpOnly; "
            "SameSite=Strict; Max-Age=0"
        )
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

    def _send_json(
        self,
        status: int,
        body: Any,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._send_bytes(
            status,
            canonical_json(body).encode("utf-8"),
            headers=headers,
        )

    def _send_protocol(self, response: StoredResponse) -> None:
        self._send_bytes(response.status, response.body)

    def _send_api_error(self, error: ApiError) -> None:
        reconciliation = error.sdk_reconciliation
        if reconciliation is None:
            serialized = {"code": error.code, "message": error.message}
            if error.details is not None:
                serialized["details"] = error.details
            self._send_json(
                error.status,
                {"error": serialized},
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
        self._reviewer_alias_authorized = False
        self._reviewer_alias_principal: AuthenticatedReviewer | None = None
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

        if self.command == "POST" and path == "/v1/reviewer/pairing-requests":
            self._optional_native_origin()
            body = self._read_json(16_384)
            if (
                not isinstance(body, dict)
                or set(body) != {"device_label", "client_kind"}
                or body.get("client_kind") not in {"web", "native"}
            ):
                raise ApiError(
                    400,
                    "INVALID_PAIRING_REQUEST",
                    "pairing request metadata is invalid",
                )
            if body["client_kind"] == "web":
                self._reviewer_origin()
            else:
                self._optional_native_origin()
            pairing = self.backend.create_reviewer_pairing(
                device_label=body["device_label"],
                client_kind=body["client_kind"],
            )
            self._send_json(201, _pairing_request_document(pairing))
            return

        if self.command == "POST" and path == "/v1/reviewer/pairing-exchanges":
            self._optional_native_origin()
            body = self._read_json(16_384)
            if (
                not isinstance(body, dict)
                or set(body) != {"pairing_token", "client_kind"}
                or body.get("client_kind") not in {"web", "native"}
            ):
                raise ApiError(
                    401,
                    "REVIEWER_AUTHENTICATION_FAILED",
                    "reviewer authentication failed",
                )
            if body["client_kind"] == "web":
                self._reviewer_origin()
            else:
                self._optional_native_origin()
            issued = self.backend.exchange_reviewer_pairing(
                body["pairing_token"],
                expected_client_kind=body["client_kind"],
            )
            principal = self.backend.authenticate_reviewer_session(
                issued.session_token,
                required_scope=REVIEWER_READ_SCOPE,
            )
            response = self._reviewer_principal_document(principal)
            headers: dict[str, str] | None = None
            if issued.session.client_kind == "web":
                headers = {
                    "Set-Cookie": self._set_reviewer_cookie(issued.session_token)
                }
            else:
                response["session_token"] = issued.session_token
            self._send_json(201, response, headers=headers)
            return

        if self.command == "POST" and path == "/v1/reviewer/pairing-cancellations":
            self._optional_native_origin()
            body = self._read_json(16_384)
            if (
                not isinstance(body, dict)
                or set(body) != {"pairing_token", "client_kind"}
                or body.get("client_kind") not in {"web", "native"}
            ):
                raise ApiError(
                    400,
                    "INVALID_PAIRING_CANCELLATION",
                    "pairing cancellation metadata is invalid",
                )
            if body["client_kind"] == "web":
                self._reviewer_origin()
            else:
                self._optional_native_origin()
            self.backend.cancel_reviewer_pairing(
                body["pairing_token"],
                expected_client_kind=body["client_kind"],
            )
            headers = (
                {"Set-Cookie": self._clear_reviewer_cookie()}
                if body["client_kind"] == "web"
                else None
            )
            self._send_json(200, {"status": "canceled"}, headers=headers)
            return

        if self.command == "GET" and path == "/v1/reviewer/session":
            principal = self._reviewer(REVIEWER_READ_SCOPE)
            self._send_json(200, self._reviewer_principal_document(principal))
            return

        if self.command == "DELETE" and path == "/v1/reviewer/session":
            principal = self._reviewer(REVIEWER_READ_SCOPE)
            self._reviewer_csrf(principal)
            if principal.session_id is None:
                raise ApiError(
                    409,
                    "REVIEWER_SESSION_NOT_REVOCABLE",
                    "this reviewer authentication method is not a revocable session",
                )
            revoked = self.backend.revoke_reviewer_session(principal.session_id)
            self._send_json(
                200,
                {"session": _reviewer_session_document(revoked)},
                headers={"Set-Cookie": self._clear_reviewer_cookie()},
            )
            return

        if self.command == "POST" and path == "/v1/reviewer/launch-links":
            principal = self._reviewer(REVIEWER_LAUNCH_SCOPE)
            self._reviewer_csrf(principal)
            response = self.backend.create_reviewer_launch_link(
                self._read_json(2_097_152),
                reviewer=principal,
            )
            self._send_json(201, response)
            return

        if (
            self.command == "POST"
            and path == "/v1/admin/reviewer-pairing-approvals"
        ):
            self._admin()
            body = self._read_json(16_384)
            if not isinstance(body, dict) or set(body) != {"human_code"}:
                raise ApiError(
                    404,
                    "PAIRING_APPROVAL_INVALID",
                    "pairing approval code is invalid or unavailable",
                )
            approved = self.backend.approve_reviewer_pairing(body["human_code"])
            self._send_json(200, _approved_pairing_document(approved))
            return

        if self.command == "GET" and path == "/v1/admin/reviewer-sessions":
            self._admin()
            sessions = self.backend.list_reviewer_sessions()
            self._send_json(
                200,
                {"sessions": [_reviewer_session_document(item) for item in sessions]},
            )
            return

        reviewer_admin_session = re.fullmatch(
            rf"/v1/admin/reviewer-sessions/(?P<session_id>{ID})", path
        )
        if reviewer_admin_session and self.command == "DELETE":
            self._admin()
            revoked = self.backend.revoke_reviewer_session(
                reviewer_admin_session.group("session_id")
            )
            self._send_json(200, {"session": _reviewer_session_document(revoked)})
            return

        reviewer_alias = _reviewer_route_alias(self.command, path)
        if reviewer_alias is not None:
            target_path, required_scope, unsafe = reviewer_alias
            principal = self._reviewer(required_scope)
            if unsafe:
                self._reviewer_csrf(principal)
            self._reviewer_alias_authorized = True
            self._reviewer_alias_principal = principal
            path = target_path

        if self.command == "GET" and path == "/v1/admin/builds":
            self._admin()
            self._send_json(200, {"builds": self.backend.list_builds()})
            return
        if self.command == "GET" and path == "/v1/admin/reviewer-binding":
            # Authenticate before parsing the claim so this route cannot be
            # used as an oracle for the configured reviewer identity.
            self._admin()
            self._send_json(
                200,
                self.backend.verify_reviewer_identity(self._reviewer_id()),
            )
            return
        if self.command == "GET" and path == "/v1/admin/reviewer-bootstrap":
            self._admin()
            self._send_json(200, self.backend.reviewer_bootstrap())
            return
        if self.command == "POST" and path == "/v1/admin/launch-codes":
            self._admin()
            self._send_json(
                201,
                self.backend.create_launch_code(
                    self._read_json(2_097_152),
                    reviewer=self._reviewer_alias_principal,
                ),
            )
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
            body = self._read_json(
                self.backend.config.max_diagnostic_bytes
                + DIAGNOSTIC_REQUEST_OVERHEAD_ALLOWANCE_BYTES
            )
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

        if self.command == "POST" and path == "/v1/admin/candidate-replacements":
            self._admin()
            response = self.backend.replace_candidates(
                idempotency_key=self._single_header(
                    "Idempotency-Key", "IDEMPOTENCY_KEY_REQUIRED"
                ),
                body=self._read_json(16_777_216),
            )
            self._send_bytes(
                response.status,
                response.body,
                headers={"Tacua-Body-Digest": response.body_digest},
            )
            return

        candidate_supersession = re.fullmatch(
            rf"/v1/admin/candidates/(?P<candidate_id>{ID})/supersession", path
        )
        if candidate_supersession and self.command == "GET":
            self._admin()
            self._send_json(
                200,
                self.backend.get_candidate_supersession(
                    candidate_supersession.group("candidate_id")
                ),
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
